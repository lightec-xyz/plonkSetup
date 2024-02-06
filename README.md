
## PlonkSetup Download
1. Aztec ceremory的文件可以在[S3 explorer](https://aztec-ignition.s3.eu-west-2.amazonaws.com/index.html)看到.
2. Aztec 的G1点个数为1亿个(100M)，大约小于为2^27(2^27=128M)
3. startIdx 越小，参与SRS生成的贡献者就越多，安全性越高，但每一个参与者需要大约6G的存储空间。
4. 生成的SRS 大约为3G

### 配置
```
const startIdx = 174  // MAIN+IGNITION中共有176个贡献者，生成srs 只少需要两个贡献者，所以startIdx最大为174, 在产线环境下，建议startIdx=0，这样安全性更高。  
config.Ceremony: "MAIN+IGNITION", // 使用MAIN+IGNITION中的文件。
confgi.cacheDir: "./data",
"

```
### 运行， 执行如下命令文件就会下载文件到data目录,并生成SRS 
```
go build cmd/main.go
./main
```


# gnark-ignition-verifier

* Package ignition is a package that provides helper functions to download, parse
and validate the AZTEC Ignition Ceremony data.

* The specs are [described here](https://github.com/AztecProtocol/ignition-verification/blob/c333ec4775045139f86732abfbbd65728404ab7f/Transcript_spec.md).

* The verification logic follows [github.com/AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification).

* May be used to generate a gnark-crypto/bn254 kzg SRS from the AZTEC Ignition MPC ceremony.

**We make no guarantees or warranties to the safety and reliability of these packages.**
