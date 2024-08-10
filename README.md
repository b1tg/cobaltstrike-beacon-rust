# CobaltStrike beacon in rust

1. generate config

change C2_GET_URL, C2_POST_URL, USER_AGENT, BEACON_KEYS_PATH in generate_config.py

```
$ pip3 install javaobj-py3
$ python generate_config.py
success write to src/profile.rs
```

2. run your beacon

```
cargo run
```
