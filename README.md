## Split Aztec SRS 
### Split Aztec SRS 
1. cd cmd/split_srs
2. go build
3. ./split_srs, 该命令会从https://aztec-ignition.s3.eu-west-2.amazonaws.com/index.html#MAIN%20IGNITION/sealed/ 中下载sealed Aztec SRS, 然后分割出bn254_pow_xx.srs 和bn254_pow_xx.lsrs 文件
4. 各个文件的MD5如下：
- MD5 (bn254_pow_16.srs) = bd136fced6a7dae869db6b058f31f122
- MD5 (bn254_pow_16.lsrs) = 078d3d314cfd57468826f567f094141d
- MD5 (bn254_pow_17.srs) = 783328d9ad1254512c5f44a8dc8f781d
- MD5 (bn254_pow_17.lsrs) = b3744ce1cd246021fccc237f27784c8a
- MD5 (bn254_pow_18.srs) = 050c05daf1c348781b3f7bab452afcbf
- MD5 (bn254_pow_18.lsrs) = 4862f0ed058e2375a763e9071bed8685
- MD5 (bn254_pow_19.srs) = 22569687e674095bdfa53b91c950bf90
- MD5 (bn254_pow_19.lsrs) = 5567b14478f76bef37ba821f1be919a2
- MD5 (bn254_pow_20.srs) = 55a2e63aa5ac916d6b334a3a4e5865e7
- MD5 (bn254_pow_20.lsrs) = 98ca7b577e821842f1ee7eebad3c1e8c
- MD5 (bn254_pow_21.srs) = 77c70ea3755523b1705d495b25ff04c5
- MD5 (bn254_pow_21.lsrs) = e4fc4c00b272449e3b2c0e2acd248c98
- MD5 (bn254_pow_22.srs) = 3fdfde15912c6d4e0c1c96acc56cc6dd
- MD5 (bn254_pow_22.lsrs) = d879adc87324931447950f7038707177
- MD5 (bn254_pow_23.srs) = ac11dd912bdf154cdfece8ab53c9fae9
- MD5 (bn254_pow_23.lsrs) = 389b2b491f451971a1a25413946b8208
- MD5 (bn254_pow_24.srs) = 5f1fce9cec36f52d87f565be132e92e2
- MD5 (bn254_pow_24.lsrs) = 9bbcfccb5828b5cc46a858d4b59661f2
- MD5 (bn254_pow_25.srs) = 22c6aab17015b39088825f7e505718f1
- MD5 (bn254_pow_25.lsrs) = 31e32274876eededecdd9a43e6b7478a
- MD5 (bn254_pow_26.srs) = 579fc27d658c7e6867a0992d5fcfd780
- MD5 (bn254_pow_26.lsrs) = cac64fa8432136e7c6aea3c4ab2cf873


### verify splited Aztec SRS   
1. cd test_srs
2. go run -test TestSha256Circuit.
   

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
cd cmd/gen
go build 
./gen 
```


# gnark-ignition-verifier

* Package ignition is a package that provides helper functions to download, parse
and validate the AZTEC Ignition Ceremony data.

* The specs are [described here](https://github.com/AztecProtocol/ignition-verification/blob/c333ec4775045139f86732abfbbd65728404ab7f/Transcript_spec.md).

* The verification logic follows [github.com/AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification).

* May be used to generate a gnark-crypto/bn254 kzg SRS from the AZTEC Ignition MPC ceremony.

**We make no guarantees or warranties to the safety and reliability of these packages.**
