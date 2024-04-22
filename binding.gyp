{
  "targets": [
    {
      "target_name": "encryption_addon",
      "sources": ["binding.cpp"],
      "include_dirs": [
        "<!(node -e \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -e \"require('node-addon-api').gyp\")"
      ],
      "libraries": [],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_LDFLAGS": [
              "-framework Security",
              "-framework CoreFoundation",
              "-lcrypto"
            ],
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LANGUAGE_STANDARD": "gnu++14",
            "MACOSX_DEPLOYMENT_TARGET": "10.7"
          }
        }],
        ["OS=='linux'", {
          "libraries": ["-lcrypto"],
          "ldflags": ["-lcrypto"],
          "cflags_cc": ["-std=c++14"]
        }],
        ["OS=='win'", {
          "libraries": [
            "-llibcrypto"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": "1"
            }
          },
          "conditions": [
            ['target_arch=="ia32"', {
              "libraries": [
                "-llibcryptoMD"
              ]
            }],
            ['target_arch=="x64"', {
              "libraries": [
                "-llibcryptoMT"
              ]
            }]
          ]
        }]
      ]
    }
  ]
}
