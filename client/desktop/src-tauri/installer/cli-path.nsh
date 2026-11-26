!macro AIFREE_UPDATE_PATH ACTION
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\cli-path.ps1" -InstallDir "$INSTDIR\." -Action "${ACTION}"'
  Pop $0
  ${If} $0 != 0
    SetErrorLevel 1
    Abort "Could not update the user PATH for aifree."
  ${EndIf}
  System::Call 'user32::SendMessageTimeoutW(p 0xffff, i 0x001a, p 0, w "Environment", i 2, i 5000, *p .r0)'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro AIFREE_UPDATE_PATH Add
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\cli-path.ps1" 0 aifree_path_done
  !insertmacro AIFREE_UPDATE_PATH Remove
  aifree_path_done:
!macroend
