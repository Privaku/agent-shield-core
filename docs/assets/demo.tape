Output docs/assets/demo.mp4

Set Shell bash
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1100
Set Height 680
Set Padding 24
Set TypingSpeed 40ms
Set Framerate 24

Hide
Type "export PATH=/workspace/target/debug:$PATH"
Enter
Type "export HOME=/opt/demo/home AGENT_SHIELD_STATE_DIR=/opt/demo/state"
Enter
Type "rm -rf /opt/demo/home /opt/demo/state && mkdir -p /opt/demo/home /opt/demo/state && cd /opt/demo/home"
Enter
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Sleep 500ms
Show

Sleep 800ms
Type "agent-shield check --shell 'rm -rf ~'"
Sleep 350ms
Enter
Sleep 2.5s

Type "agent-shield check --shell 'cat ~/.ssh/id_rsa'"
Sleep 350ms
Enter
Sleep 2.5s

Type "agent-shield log verify"
Sleep 250ms
Enter
Sleep 2.5s

Type "agent-shield log tail -n 1"
Sleep 250ms
Enter
Sleep 4s
