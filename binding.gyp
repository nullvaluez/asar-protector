{
  "targets": [
    {
      "target_name": "binding",
      "sources": [ 
        "src/encryption.cpp",
        "src/utils.cpp"
      ],
      "include_dirs": [
        "<!(node -p \"require('node-addon-api').include\")",
        "/usr/local/opt/openssl/include",
        "/usr/local/include"
      ],
      "libraries": [
        "-L/usr/local/opt/openssl/lib",
        "-lcrypto",
        "-lssl",
        "-lsodium"
      ],
      "defines": [ "NAPI_VERSION=6" ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ]
    }
  ]
}