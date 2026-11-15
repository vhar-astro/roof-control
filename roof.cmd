@echo off
rem roof.cmd — LAN-only roll-off roof control (no Tuya cloud involved)
rem usage: roof status | roof watch | roof open|close|stop --yes | roof set ^<dp^> ^<val^> --yes
node "%~dp0tuya35.js" %*
