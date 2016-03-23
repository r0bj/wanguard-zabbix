wanguard-zabbix
===============

Add script name with parameters in wanguargs GUI: Response Configuration -> While an anomaly is active -> Execute a custom script by Sensor -> Script.

Add notification:
```
/path/to/wanguard-zbx-notify.py add {anomaly_id} "{sensor}" {direction} {ip} {decoder} {unit} {severity}
```

Remove notification:
```
/path/to/wanguard-zbx-notify.py del {anomaly_id}
```
