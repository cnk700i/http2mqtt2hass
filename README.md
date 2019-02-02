# 配置说明（configuration.yaml）
```yaml
#{HA配置目录}/configuration.yaml
http2mqtt2hass:
    broker: mqtt.ljr.im     # MQTT Broker
    port: 28883             # MQTT Port
    app_key: xxx            # 获取的app_key
    app_secret: xxx         # 获取的app_secret
    certificate: xxx        # 插件目录内ca.crt的全路径
    tls_insecure: true      # 不变
    allowed_uri:            # 允许本地访问的路径
        - /auth/token       # HA的Oauth服务地址
        - /dueros_gate      # 小度音箱插件服务
        - /ali_genie_gate   # 天猫精灵插件服务
```

# 更新日志
HA 0.86.4 和 HA 0.82.1，天猫精灵和小度音箱通过测试。
