//! Fail closed when a Linux socket's device binding prevents redirection into the TUN.

use anyhow::{ensure, Context, Result};
use crabtables::sys::{NFT_TABLE_F_OWNER, NFPROTO_IPV4};
use crabtables::{
    Batch, Chain, ChainType, CmpOp, Family, Field, Hook, PayloadBase, Policy, RuleBuilder, Socket,
    Table,
};
use std::time::Duration;

pub(crate) const TUN_NAME: &str = "tun-aifree";
pub(crate) const XTCP_OUTPUT_MARK: u32 = 0x0a1f_0001;

const TABLE: &str = "aifree_stun";
const CHAIN: &str = "postrouting";
const UDP_HEADER_BITS: u32 = 64;
const STUN_COOKIE: u64 = 0x2112_a442;

pub(crate) struct Guard {
    // Holding the owner socket keeps the table active. Closing it removes the table even
    // when the supervisor is killed without running its cleanup code.
    _socket: Socket,
}

impl Guard {
    pub(crate) fn install() -> Result<Self> {
        let family = Family::Inet;
        let mut batch = Batch::new();
        batch.create_table(&Table::new(family, TABLE).with_flags(NFT_TABLE_F_OWNER));
        batch.add_chain(
            &Chain::new(family, TABLE, CHAIN)
                .with_hook(ChainType::Filter, Hook::POSTROUTING, 0)
                .with_policy(Policy::Accept),
        );
        let rule = || RuleBuilder::new(family, TABLE, CHAIN);
        for interface in [TUN_NAME, "lo"] {
            batch.add_rule(&rule().match_eq(Field::OifName, interface).ret().build());
        }
        // This mark is only configured in the supervisor's XTCP rendering. Require a
        // privileged socket so a packet marked during redirection cannot use the exception.
        batch.add_rule(
            &rule()
                .match_eq(Field::NfProto, NFPROTO_IPV4)
                .match_eq(Field::SkUid, 0u32)
                .match_eq(Field::Mark, XTCP_OUTPUT_MARK)
                .ret()
                .build(),
        );
        // Reading the owner UID limits the rule to packets from local sockets. The
        // kernel skips the match on forwarded traffic, which has no local socket.
        let udp_length = Field::Payload { base: PayloadBase::Transport, offset: 4, len: 2 };
        batch.add_rule(
            &rule()
                .match_cmp(Field::SkUid, CmpOp::Gte, 0u32)
                .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
                .match_cmp(udp_length, CmpOp::Gte, 28u16)
                .match_bits(PayloadBase::Transport, UDP_HEADER_BITS, 2, 0)
                .match_bits(PayloadBase::Transport, UDP_HEADER_BITS + 30, 2, 0)
                .match_bits(PayloadBase::Transport, UDP_HEADER_BITS + 32, 32, STUN_COOKIE)
                .drop()
                .build(),
        );
        let mut socket = Socket::new().context("opening the Linux STUN guard")?;
        socket.set_recv_timeout(Some(Duration::from_secs(2)))?;
        let outcome = socket.commit(&batch).context("installing the Linux STUN guard")?;
        ensure!(!outcome.responses_lost, "the kernel did not confirm installation of the Linux STUN guard");
        Ok(Self { _socket: socket })
    }
}
