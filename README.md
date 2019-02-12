## Encoding benchmark

This code provide a benchmark for encoding data by encryption.

It compares if it's faster to encrypt a full JSON or encrypt each field of the JSON.
It also compares the decryption.

Here the transaction JSON used:
```json
{
    "address": "addr", 
    "type": "1",
    "data": {
        "encrypted_wallet": "XXX", 
    },
    "timestamp": "1549488623", 
    "publicKey": "3059301306072a8648ce3d020106082a8648ce3d03010703420004035187cb1b21b3cf24afa631c97e17e5a48d69d765d1ab82170508ecd6d376134bbbeba132d7c94041f4b0e374704544dd879639ca25d67f58d2f9a8b6862f73", 
    "signature": "304502202222145dd82807eef22497cd101ac054351be1b843f7e3fc256f22ae9277ccde022100968561e30bec1bd38360b6b3986b2859252a8dfc9cca80ea8353287c6845e854", 
    "em_signature": "304502202222145dd82807eef22497cd101ac054351be1b843f7e3fc256f22ae9277ccde022100968561e30bec1bd38360b6b3986b2859252a8dfc9cca80ea8353287c6845e854"
}
```

Wallet:
```json
{
    "services":
    {
        "uniris":{
            "key":"307702010104206dc83657425927d96ad5b51559f91f97caef79dde615e3abcdd0ce78b4f90f23a00a06082a8648ce3d030107a14403420004dba6e3e8a005aa3da52b12bda6ab139ae878273f144942572eab9f5063545ef8860472068dfd3e0a9b08db8b889499592039d16e3deeb9f1616f9897d3223542"
        },
        "gmail":{
            "key":"30770201010420d51c0e849db62fa07f7d4d11686755138b05d6af115ec832ceb6877b77ec9410a00a06082a8648ce3d030107a14403420004db5ac66818f97f188116aa39521cf46f3547dc8b3216cf7c68a332a8b8c76a0146bc9135c8a3f8f5a88cfa4b98a5fed8aacf31fb447203ed1d5f949771bc8835"
        },
        "ethereum":{
            "key":"30770201010420bee7673ae54f4ced217e8779384d3a584142dddb4a2643b027c435c1ba135ab2a00a06082a8648ce3d030107a14403420004369627abb91167bef7b8f9b4a5698b61a9dc6ef116dffb77fd85efe58d2ed8a642103d5b30a1afa2fbf68cffb88e88e87b6458c1c948407e3557cbef8e5529db"
        },
    }
}
```


```diff
$ go run main.go
-----------------
ENCRYPT FULL JSON
-----------------
044838d58dd5b61ff809d288115acaaf846c85f7b88268f3d31ab6c67bf04c77b2db6aa0eaee13b8146a5b1c1911bfc904b2e53d9c7e7a3f619a10c3d8434b95aa05107a1d658a016b33afd809e96cbce9d1d12c51ea640e5750e5baaa818bc86da5fd1972d4b29781de72dc1d7cdcf2932692b5daa51f76df3dab7eb1c87c4f1579fd795c4fe00438da22d823ca9b9aa7a80cd3256f76f64407da5f7ca3baad62b723b87380df475936907328a69914d692a76bbe93d5afb0470e723f04860170de0b58496d9398d1204a9094afd554fcaf83726594b1f5fd29b55ee7536e55f2209558bf98e613ac731e76db98f3658e79377906e1ab950733bcae0b04e43073b2b4997f76a70ac8d30d064c9d384a4767e511e561b6bcd375be23b58423470f2c61ee6d4ce21b3d6a73ef92461534116aa97062afa78f50d3e92c90d4745a1db68c6281946d38d712c9c0d468f2a2e617136c8e7e1e8c36e0b2380c23fd5d65dd43a50e8ec1882666f55b018e64f74dccc1af5c7fe72fae2d11a26fcd56b289a8e286bf9f39e31c5498f716c69449a738275ddd4a3cbef2e13d9c1a8fe7404ea18131904d83e7f375b3bbb32996e49124754156963a435cc60166960581e91fe70eeb1d5e0554dd245bf9c6cbaad86171d2556b55b8f9751b8b42fc83761ae440ff19f42c27afbcde298409a37fd33472550de820ea999df54a91157790dd390f1350fbdb8d6732ac2765470cbeead8da1b2f525f5704e87405105d7a1c1551223aefc93414e8082008f879027e2c81913a0d450e797bdf4f06aab288b1a28429df0e4f3fdedeb219254726de40f216c21dc9446dce111114a382782fe292725e51b166c155454b6627ff4e64b62a20ef909d9301e9fac6e163d0ef4054bc44073df5f7ce221a33620fe74f0af7527180706a2ed9fe96547f1f2d3d5a4947c3f909b48051d0053dd4bb465eb2df09ffd8f0ee6fd7a5ef853e7cbf598028238de7e6b631f265c77f14f4a2c7f3db71723961301e5f269c394bcb93c98d7bb2639bc6cc2c07de98c7facfbb555bb204a0fc631c8861cbbf547f8b05b18cc1df54b0f3356616ddf50dfd712cd7dc0a123bf8d99b26b11856a14153fa840ee61976fa1431c6d433fce1e383062fc57e5ed7462cfb8289fda1245651ac5db0921d0421aebd4fbf34b21f51e5b5be282d4aa42589ad6e2991d1e1b721efbf938755e3647bd015e9a66f63fe7fd196f3aab315aee1d43b7106f05c6b8db112ffe4ccc42fc0861d5396c8be68ca3d985eb7a67ec6ff512bde2e653ae56e9a3453f702eb5510660aba6cf9b6df5c9fa2222e9c9169dc42d10edd0afe46d1954c8aed3c0ba8ad7ee46305e120ee2929f2fd306da5788d3d00623ccc9a953cf747c4b9edb1c93e81f96fdbca431b8736e5cfb4a7321b4c1afbbcd595166b049184b46d12f5de14f08d6f3241e51c26713faecfdcb93462172cb8c1d35549d14c9faae93ac62ffd099fd1d2916334f6a935f88222828d5c968c3e6283240c67f5da673e5c51df388789bcaf47e7374e1dd91fb0d74796e06beb9114657388f9c3e8b56b92e8efefe376802bd0ea782e204cb11e5578bc475b3eac2884bbb4e5a9a1b207574b3e0655199e454ac7045df9349c747e2fb6c95bcd95941e4b8e0865ed98a2624f27670a1eae6089d1ede12594f7fd7dc2dfe4e95dc018180ea68139e484451b68180d3848f5e2eecf55ca690bd3a58510add0957db4d56b5efe15d95c0ac414050a653f4180b7a7610b92b1723da56ffb258c04cf941fab9e4f01f45635c595e2390ca651b5ab4f4fe5d74f90fced82f62d4ff7ca330c821f41b4199fa94a7fd374dc9d9e2c8f2aadc3ec58e381e63ccebce6887de659524aeea5d93e5eee11e0d880ff66da22a38250c312eff2253a6e1254a28f53cfb3d0592acabce0b0f8ed7ceca88d97a48dff2c686d9f5b86376b9c4d9d17e87a0bd855bd4dab940d09aea464b099b6cf29bb2ed5e97f3f2abc88e8cee0d18db816792dde58d089cdcbdb8a4390730e023ece69980d32b0d32606c1d0b3e56b8b85eb993ab7de2e9689aba49da2a5866bb7304c7fe81a7e91ed310fc18e9e5d5303f0bde30ac6c1d1352b253e00e60fccf4d7c6fae53f7cfd429e742221243e439e9ae68d92505442abbf37bf706a43d98ca05751da7f76f05f53faaea1bfd82ba897b3f0c171ee4a34e8f4ef00675ea8812b165ccc5ae790ab4397f8b8b87976d1ba3508bf6b7ba82f0ea09f43a09ffb156b8910bc7bf4d652e55e443394fe6dbbb5aa3e76b556ae86881c1bdb43a3d83e927ce3ee4f9eab6ba792352718a38d20cd6198cfaf19819473d101aafeb489be32105eb1626ac57d748b2df069262487674412bb948a128c18abec881044a120bfebd58284d7d9e191fd853f28664ff3dcb9e39e160e7dd883ca0a26e4eff67c5c9d7ebdfb40898cd0164ecdbfce8838afc5ae922a19391dc12bb2302a5d46e414bf7feb99ed37e638e72000527cb22da0c3f3494144feee634bdfc968edcb53c91da9354e1a35d18b15a2d8b205cbd64fdefdc690e035270189e29461f203f4fb8883d470da07f83b7500da48ffdc79756cf9c2a557559d9c6e4b586ade5165a4777efbb7e444fdf41212d02ce74719fe796da4488d452beff9a46a3c86836bf61a5706aa6c332cac7f710d5edffdf39697be90ccbda98c54f0e231fec9e4f917e813c720ba7e620436ebc76507650ac4253e336710c5977c7253687bcb497573a1dcd771b9ac840316b97aa062a511ba7fbc402d79dbfd480f66a71681993fa397e0428e51cfb30a4a58e1acffc6de126234234f0d0739eb288306f08de0134f8dcbefeb9b1dbef8bca577a2565f3f63c3686c959fc1f79b450d1359e164f91f5881ea47109d6d313a6cb9c583189a95815927be2850c524b1315caf603a531018a6445cde28ffd4e0920490f0bc1075c9621a68e5af2f7c4fc5348338465fd66bd0e3d3f722761d64f2176712945c7c4e1deee3b547be67af00dd41aeb0860ee27b16552f46da9f925f3c626bfae6a8576a3071bfb117ef8a21ec671c093bf9a82dd1db284932e5e6ecbe5834f0600e1249ff79cfbef3642588ce10e381955f36c30ee72ab58e284944d743f5f3fa4eed33409f6a7f4817cef62e3df18e4c6c894d3faabf322688a6d17745e265e1ae375e3d7359b45bf428b4f621ff7c2de39b5c6d217fb3f4f1ca3cd5dc1377a135711b108e4b07bf6419fbeedc57c2b0e599097cce2c7d4722afa8cb990a75782978f4b9042f3f9120308c7bde291f2a96b1b8b7bfbcd15fedee6f09914f7c5d564dbf9edb26
====> Length 2366 bytes <==== 
====> Encryption took 0.083646 seconds <==== 
-----------------
ENCRYPT FULL JSON COMPRESSED
-----------------
04638833a60c2f89066cb0260ad1c8a02df16d622b9b341ea640ea48969bb5446254094a4f3a9d77d3e30c4fbd7aae9104587e06ef6b7b34dd350a937cd739f283cc404404ab6ec4fc60903faf3d77f26e33f85426737da8c599ba95557ca0811892ca72d1d0c8006173fa9901498af07a49e8af1792f47a351bc81db2ef67fa2b1ff738c8f822780e39b50516c44ad724daff1a034bf984fa0374f4ec8298b8e3d315eb64e6e678ad1cbe4f19b46d2f9cc971c6a0e06e1b1ef7c07c2a91c99d74bd62bd459fe36ba3ed9a1e4eb2d14e3f749d2cb992ea4e4fa0dec7aadade89d8bd730e5392a36a812ee4a847ea15307dc86a641e38fc01716d173d56cc4e2b8adbce2b594a3c4ed2de92700a1418d5157f5dfba643b34e174aa997e0e989db34cd41a3987983fa95db95a1c78f959085e3f743b52b406df11665fb49253a17e7eb8a8b6bace99e89b3b3ba5caf9733d560bc18fe5b8c6f2c84d4b8529f7a38637700c2289c29c1ad70af5c724ed6c0d318c6f1a52373c6d2b721292c5cabd212db4ed405360c42869541691fffd0d523e8ea6ca4e09a1273f3a9cedb81ae1e389237e2d05c649b85ea2663de27dae00d5b993d6241670701f94ce601da837f2919335b301105153db7a466e9d5781248bf55b959569d4307e7a26118e462212f579b73b0a9a771458b68b15f18dfcf04057e0d13533b11ec2c37465387c04d1ca5fe518ec8cc443e1f1a2c3c7fc085b47c82459cec850b69575530fc71ee29cb343fd50a4e900e7d5360657ec6084d240c339c9d718f733579c69c171e6527877cc513624c8b38e889f0a60f725c2625cac5e04ae3210b884b8d58c40fd2499636d2587fd4766505a14f56b2b0980cf22d6397b5c7c28512c8cbf57ae5f7fd63ab240970220922983cbe279907152bd7463aea4afb5aa99cc28f8fb60a65caa18f9acc2d1f8087dba246357fd670c0ed8cdf14a34b9da5cbfcf6ad8727d3d6c341bfcab5dd4b259c6d40ddb1668f42b79e46490472dda2a5a401e853ca48cb96bcf7805af6b722d506daebc166737106019b407b2499b89d33fb94afdbbb376056b7a60f08c7ab24c989e585494cf941ef782a5bdcbf53ed61ba6893307754147d16b95f138b3b52698cc23290523ce97a14e2a9b92af1beb1d0542120bd17a99dfccbe8813150893f49927fd73d9375d353cce1baf5238f412421b4b47590bf3428ee4efa02498d42f215c10ba5b265b4cd3f9bcd5846b025ddfcffc34a09017316da4218f13f4aeb62c7310d5eb1117c3eaa0a1741cbb792390a3160083e7d708c
====> Length 931 bytes <==== 
====> Encryption took 0.088477 seconds <==== 
-------------------
ENCRYPT JSON FIELDS
-------------------
{"address":"042faa9659b55130fb6f85816c44c1ce7c57c872e8943013ffe2af34f805266fced4f49c8765abd25b54088ab9de8623bb6c463d2580d0f25dd1d0d36926bc26aa77172e6fcf0ea2701567d63e867836adb48fae4be3000d79d770b7aba4566abc9d4bd9cb96021e9430765ba9eb68c2a1deba0c89","data":{"encrypted_wallet":"a8f8ff6b1dfbe4d071c8854c4bd331d707044ff79b42a14784a2e8194c599da31fe8a44930c0e885ba17fdf68c209e9ec668d86d883be619134e4e2b369f0712a529f7f2e7c6a3412c0dfb4edf7327c29eaa935acfae069f969b88d9c6e925421b7c5cc0dd51a8de04872c899c820984c528d5d73374ca7a7bb435a6ea2f6e05ffdcda7618d5d503749cb4f2f8f87889d545054b7082d763d34a9c55d88ddaf3cb7d690c6a484f59cb235b0d7bea05ccf77bfa3357278b7fab008ed4ff3be677c4ba977d236c924fc4484df5910d907508b6b3ecf95dab0e8b8c975d51f5430c1a6a4ce9d6e4d8a82130f4fe5ac325cafdd789aacbccba41cacd45ba0eeaac505ab9b133a823d58837bf3fb087736a6d13a8fd025d6826d316a5f6748622d8c39f008264e71ac3bccdb732bfecc23fd7600015fa7266c28ee95d2e47bf685fa0c3c5c9e8c0057e9845962b530ef061c97ed7caf8ab4da54f1617f2402bd1f68e71b3eb2f3038f20c512493baf32dfb0c09e55f938bdb7cdd4776181e541fa6f14ed102b3c985f3408615ecc98e1ef6162af6364c8d4b0aedef3d99fb15e35f6189fd404e250fc7f2a0eca5a7b1e9b0f8491311473ef91fc7a1f30836efadb2e50cabd8c1ea1c8c1bfa9ca132f69e53f5e96e1554988279176ca37ab9873c7f3ee4e4046aab501f1414880e5f59e0b47a1c06ec4a99a287553da7835caacefd709c6fbc49cc80d5487402e4b8537dc9fe567cbf325cfefafdfabfb0c7b5b37294f7d5192b7b5a236842c2eb529dcabae0f234dad923ce2401031aab1efb43b501709a7e47c4c710e778a268ca46ca554b7a3158b008b06e747b2062ef081674327f13cb2002026015245f05f13ea293881dc2fe852ced683abd9a606d87e1c98b17e9baa9ecf1b13caf54e2a0514800146e8fcaa29554de347ea3d7417801a8322ada82f72fd01740a5a8eb68356a2bc49d6217e75285d844f1c5aa9d251dfa0f42f0a52174d0205852c937b492a157106219b55d575291b2e15b4f65b9ccabbdbc9200f4c7d5266548c8787a5199bda85ae7bfa577810b9906d8d4c0fb393ed2236ee55747ef55934e8df138864ab2d28cd37ebcc5028b9e82711f3b3edd1376d9f70400b5d74837e76e8f6b0e95cb503c743f2baad5bec520e233ae45"},"em_signature":"04698e8fac2d41103995639cac3537a7157dc16123ede8886b483d8ee8d81bae584183fd70a2a3591a11ab909e06a8465c9a716b636ec0a988bbd9f27feb6175bb4427959e70fba2c60eb908a54a36100a6a024ecb1937d6290879791a18565e8a6e5d0501be74f78eba1cfd93d7ad466e691efe9ca1a5adc70992f13cf03caa81c68cb0543e0099452dfdcac1ecf6c6c8d2d06657a0f798b33b8038b9310ac7d78ff6b025cc5add0656e33022ba0a87ddf08f58430e7763fd3d924db170fca67e969fcbe16217658e72149b637e14911bc4f696c10c721817d7d20d94e07f1968218d79815abb7a4b143e60ca6613bed6a5a58aa7f11b55cdab069ee95a30","publicKey":"04f16805b4e95a086b9895bf3adf57fcd6ad1231590f8b8f22a6e5efd542b09366968227d465f8c23461b7eb5c0bcfe600b6d5774991d86ff35a10512f19e9bcd0fab5d4a9fa1d8e2cb0ca548c32f82f9ca6db6d0a3a3d9b5760627bb18ca4cd4e60c00784799f5b1f3e5026adeff4be5230ae789eeddd4208bc2200573a2807311f002a67d45a07410d173c698d4ca8c90f8b62bc9087c18e9103dfd16049099ec83f4e7b304bb57fe9ad1043fba1a2efda83ffc59eab999af66402733f0b673799a04a936d6a26c2701ea3a07b9d6e5c83297eed02561c001cd37c17953f68384824b44bdbd811340c5ba16e9e430c44dab15de11b74ff305db4fdb27a9ecb88f32525a75dd6c59cd3917defd1f6edf8f61837fd4c5403cf8a1ed250046e5f25c0cf20c5c3b5","signature":"04fcd4b035ce9d122c978f01cf05a7550c728d581cfd1381e9df2bac1d77e202858b1481350adbf7ef7b60e073e4afde69ebce7c87968a3778883d43cc7cdae0ff387f9c35d7e902fe502f29ba48ee54661f23cda77ed15c6cd1903b7f1c96ae449e763e9181d5e5ef776f69332b81f1432d20f5bc8d55c6309c18c4df89cdab9d40692a40dca3637d34178be21ac7adb416e9d805c82738d759671b3fa891e40a2e931845f67923233044d1bfdc7b41b822aa32e90881ea25fdc3055a6943bd836d207b1c92fcec5ac6642c3927e892ec8f4bcf7a36b27999b98969f2c530145e5520b844b3676ad60a68229e9717299f67fbd458d229b8761a8fc23b4442","timestamp":"0484ea24300604cf1193118bf62af3d06a1f3387552821cc98e86bf48f06e892d22e644778b8ebc18efe7fc93c87fb8f2d09312d025077f6e7bfd2fdf19ee17ef8610ec581457c515840dff6d59196bcfcf2e0ebb2ffe75998fa63190af0f06951824da67e3a008fac2bd6da7736cd7fa06115e749c56c4e87a418","type":"0465864ec8d415cc409be0656410c783ea2706b13a0443382b186f61d24767aba8a23b2a746635c344c28993bc0ab3eafeb87810d4d15d06e0d9516f3ce294476e5c65c3313d2307c05c9b5e1d1d7de09af7250d46a7ce13546aa1a077962f935d5004ad42a211a87cec04b48fafd8d27b2f"}
====> Length 4094 bytes <==== 
====> Encryption took 0.087526 seconds <==== 
-------------------
ENCRYPT JSON FIELDS COMPRESSED
-------------------
{"address":"042faa9659b55130fb6f85816c44c1ce7c57c872e8943013ffe2af34f805266fced4f49c8765abd25b54088ab9de8623bb6c463d2580d0f25dd1d0d36926bc26aa77172e6fcf0ea2701567d63e867836adb48fae4be3000d79d770b7aba4566abc9d4bd9cb96021e9430765ba9eb68c2a1deba0c89","data":{"encrypted_wallet":"a8f8ff6b1dfbe4d071c8854c4bd331d707044ff79b42a14784a2e8194c599da31fe8a44930c0e885ba17fdf68c209e9ec668d86d883be619134e4e2b369f0712a529f7f2e7c6a3412c0dfb4edf7327c29eaa935acfae069f969b88d9c6e925421b7c5cc0dd51a8de04872c899c820984c528d5d73374ca7a7bb435a6ea2f6e05ffdcda7618d5d503749cb4f2f8f87889d545054b7082d763d34a9c55d88ddaf3cb7d690c6a484f59cb235b0d7bea05ccf77bfa3357278b7fab008ed4ff3be677c4ba977d236c924fc4484df5910d907508b6b3ecf95dab0e8b8c975d51f5430c1a6a4ce9d6e4d8a82130f4fe5ac325cafdd789aacbccba41cacd45ba0eeaac505ab9b133a823d58837bf3fb087736a6d13a8fd025d6826d316a5f6748622d8c39f008264e71ac3bccdb732bfecc23fd7600015fa7266c28ee95d2e47bf685fa0c3c5c9e8c0057e9845962b530ef061c97ed7caf8ab4da54f1617f2402bd1f68e71b3eb2f3038f20c512493baf32dfb0c09e55f938bdb7cdd4776181e541fa6f14ed102b3c985f3408615ecc98e1ef6162af6364c8d4b0aedef3d99fb15e35f6189fd404e250fc7f2a0eca5a7b1e9b0f8491311473ef91fc7a1f30836efadb2e50cabd8c1ea1c8c1bfa9ca132f69e53f5e96e1554988279176ca37ab9873c7f3ee4e4046aab501f1414880e5f59e0b47a1c06ec4a99a287553da7835caacefd709c6fbc49cc80d5487402e4b8537dc9fe567cbf325cfefafdfabfb0c7b5b37294f7d5192b7b5a236842c2eb529dcabae0f234dad923ce2401031aab1efb43b501709a7e47c4c710e778a268ca46ca554b7a3158b008b06e747b2062ef081674327f13cb2002026015245f05f13ea293881dc2fe852ced683abd9a606d87e1c98b17e9baa9ecf1b13caf54e2a0514800146e8fcaa29554de347ea3d7417801a8322ada82f72fd01740a5a8eb68356a2bc49d6217e75285d844f1c5aa9d251dfa0f42f0a52174d0205852c937b492a157106219b55d575291b2e15b4f65b9ccabbdbc9200f4c7d5266548c8787a5199bda85ae7bfa577810b9906d8d4c0fb393ed2236ee55747ef55934e8df138864ab2d28cd37ebcc5028b9e82711f3b3edd1376d9f70400b5d74837e76e8f6b0e95cb503c743f2baad5bec520e233ae45"},"em_signature":"04698e8fac2d41103995639cac3537a7157dc16123ede8886b483d8ee8d81bae584183fd70a2a3591a11ab909e06a8465c9a716b636ec0a988bbd9f27feb6175bb4427959e70fba2c60eb908a54a36100a6a024ecb1937d6290879791a18565e8a6e5d0501be74f78eba1cfd93d7ad466e691efe9ca1a5adc70992f13cf03caa81c68cb0543e0099452dfdcac1ecf6c6c8d2d06657a0f798b33b8038b9310ac7d78ff6b025cc5add0656e33022ba0a87ddf08f58430e7763fd3d924db170fca67e969fcbe16217658e72149b637e14911bc4f696c10c721817d7d20d94e07f1968218d79815abb7a4b143e60ca6613bed6a5a58aa7f11b55cdab069ee95a30","publicKey":"04f16805b4e95a086b9895bf3adf57fcd6ad1231590f8b8f22a6e5efd542b09366968227d465f8c23461b7eb5c0bcfe600b6d5774991d86ff35a10512f19e9bcd0fab5d4a9fa1d8e2cb0ca548c32f82f9ca6db6d0a3a3d9b5760627bb18ca4cd4e60c00784799f5b1f3e5026adeff4be5230ae789eeddd4208bc2200573a2807311f002a67d45a07410d173c698d4ca8c90f8b62bc9087c18e9103dfd16049099ec83f4e7b304bb57fe9ad1043fba1a2efda83ffc59eab999af66402733f0b673799a04a936d6a26c2701ea3a07b9d6e5c83297eed02561c001cd37c17953f68384824b44bdbd811340c5ba16e9e430c44dab15de11b74ff305db4fdb27a9ecb88f32525a75dd6c59cd3917defd1f6edf8f61837fd4c5403cf8a1ed250046e5f25c0cf20c5c3b5","signature":"04fcd4b035ce9d122c978f01cf05a7550c728d581cfd1381e9df2bac1d77e202858b1481350adbf7ef7b60e073e4afde69ebce7c87968a3778883d43cc7cdae0ff387f9c35d7e902fe502f29ba48ee54661f23cda77ed15c6cd1903b7f1c96ae449e763e9181d5e5ef776f69332b81f1432d20f5bc8d55c6309c18c4df89cdab9d40692a40dca3637d34178be21ac7adb416e9d805c82738d759671b3fa891e40a2e931845f67923233044d1bfdc7b41b822aa32e90881ea25fdc3055a6943bd836d207b1c92fcec5ac6642c3927e892ec8f4bcf7a36b27999b98969f2c530145e5520b844b3676ad60a68229e9717299f67fbd458d229b8761a8fc23b4442","timestamp":"0484ea24300604cf1193118bf62af3d06a1f3387552821cc98e86bf48f06e892d22e644778b8ebc18efe7fc93c87fb8f2d09312d025077f6e7bfd2fdf19ee17ef8610ec581457c515840dff6d59196bcfcf2e0ebb2ffe75998fa63190af0f06951824da67e3a008fac2bd6da7736cd7fa06115e749c56c4e87a418","type":"0465864ec8d415cc409be0656410c783ea2706b13a0443382b186f61d24767aba8a23b2a746635c344c28993bc0ab3eafeb87810d4d15d06e0d9516f3ce294476e5c65c3313d2307c05c9b5e1d1d7de09af7250d46a7ce13546aa1a077962f935d5004ad42a211a87cec04b48fafd8d27b2f"}
====> Length 3372 bytes <==== 
====> Encryption took 0.092381 seconds <==== 
-----------------
DECRYPT FULL JSON
-----------------
{"address":"addr","data":{"encrypted_wallet":"4750f8abd087102f915c56db77640f7f3f2645f3bb55689042a2631ab03441547a18ab78da8487b37cc4de8e68462b72ca7879fbd822bec5194d29a0bd55e47cb5af7fd31d622103762fb017ccd0c960a88c3827bd004f39f5e86224c2552e15485c05e1c85d42d42c5cf7aa1f5799dd5d8b695c89e8270313d768bc7b82cccef92807078027d51d678602b8ee4a899d1ae0346f06ab46a36288e3d474513b350ecb6bf7882cd39c5690c5e3f5b9616debaadbb5be6767878d3a3634fceb5e7ff82f9136830ceba06febf6b3a49b97e48a38d5d634dbdf416a6d9008db0acdc13a2a76f91a6e356edc9729c82c67324b8f8795d395e6d2b72238860304c520f2a08e25e35fb3923134e5cbc336fe0ffc0cd47adb233716debda14f8566c28b19920636be996dd041b11b0b0b6f3a464e182d941d400a7a5531aa0c6cb085343a1303b683396fc1bf035e4867f70707a13871079cb4021e10b1cc275da4dc8a8e013bfe4c594f517ee23adbc2318e10f624c76efa9f63184abafd3b3915f38b2040c3ea6726d553815cbfe64febac2a46fd87cd5b72c22e9c3b8752026c811a8207c6d0bfc3076bf3dabd52ec64df3eb3cc37c15d274ddbc7d8a16c1e9cb1faea9fef94509d9b1f0958ac3eed93a32511570d6651e85ae36d53e2ecf65407f959e8d72cccd2836ebe45c7790d981262e223a0688755410bd36bb8618a2bb5d5408a9e2f6f090875390094ae56f5a0b0cf3d21ce0ec7e554b699fc7f618e077917fa5cfa72cdb3d8f0e10731263595276a2de1b276a866624e45a05ac29d56b066f02ec92cc9aaf5701511e768700dbae8d964298a8bfdaad20f30d797e37759b6e9c84ec2a421a7e965e6bdb10d3e8f9bf2a94aa26e837e620b0d549f9933fa70286a3db21cb77488f4a4b547aa865a165ed8d728d1fc47127bc1f8b269a8c501ae23d43b0c35abb811aea16e1ff0c2542e9af74a995d456685d4a400f5c33e415c576fc56c26a10a1eeac8641d315d9729b22a369fea4c660141806c81519746b50396145a96c22b298e069cb01a64375b5b3fba44b34f4d558114a99f395bb4a27a6b8fcfb3af305ca76d60fa7d92ec3784f5e5c3a04ebb2311bf091cdd0867d5bd7cd14cc8e2cd8bafcc5eac2373625408377fa78e9d237769b03ade"},"em_signature":"304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf","publicKey":"3059301306072a8648ce3d020106082a8648ce3d0301070342000445b9f869f288cccb2f07e49fb4e3a776219a02c637b52201628ce98274edc8221b6c562d4ccf19d0aa1f777edae115e43e8e48af1c3b8649b8b0abe3a9edade4","signature":"304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf","timestamp":1549976870,"type":1}
====> Decryption took 0.000378 seconds <==== 
-----------------
DECRYPT FULL JSON COMPRESSED
-----------------
{"address":"addr","data":{"encrypted_wallet":"fd0f8f9479d580148c41016d97d3cb177286fc28b1eaa976cdb0a89f28171967f48c4a4f95b2b03f438f64b0d41342fd18a2248a5f523ec1a2f1ea4a46dce1a042e51720615193b63eed446cbaf9e7ed4c9d6425c74595d620f116e19a90dcb9d012480d50be607a1e1d1b5cdd9e8da5492be0d903da8ab46637ff7da9143d6e76c2518b1b8101b24424bbaada0fcc43ed2824e8186cfaef828434bcf47b701393e39a994d20108e9cc5c3296adb041f52dcb561782cbed412f221110b7d4e85f22615c4ba283cbe307a57856f38b5bab49043aa0d4bd9399cd13866360dee8bcc9d1946f6001da493b66250062113442e5cadf59ca82e2ee485bc9baefc32707505e9e7b83102855e96ce70d91d6af037623c7592cfcbaecc12370bb38c27d0243d986e03c10649c357e79ef1782b4ed0285b681d2b9a9e7ee8d3cadfb491f0898361d16f1af407337b8db2092b7292c07916349eeb61efd69ed953b17069893cc22dfe3198eafb2992f041062980e234405439c5071c87e21808f2ca642866be9725196b37fbe7efc207321cd55a2e291a151d8162913e9e23d248350b8a5df16d798f12f3af3196ac5a49e2268a83c4760ec745454495edb7bfece1691ba5bec04aad3a106ae8687ff734aab6d0ddf802322bd0f0b363"},"em_signature":"304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf","publicKey":"3059301306072a8648ce3d020106082a8648ce3d0301070342000445b9f869f288cccb2f07e49fb4e3a776219a02c637b52201628ce98274edc8221b6c562d4ccf19d0aa1f777edae115e43e8e48af1c3b8649b8b0abe3a9edade4","signature":"304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf","timestamp":1549976870,"type":1}
====> Decryption took 0.000224 seconds <==== 
-------------------
DECRYPT JSON FIELDS
-------------------
address: addr
publicKey: 3059301306072a8648ce3d020106082a8648ce3d0301070342000445b9f869f288cccb2f07e49fb4e3a776219a02c637b52201628ce98274edc8221b6c562d4ccf19d0aa1f777edae115e43e8e48af1c3b8649b8b0abe3a9edade4
timestamp: 1549976870
type: 1
signature: 304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf
emitter signature: 304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf
====> Decryption took 0.000500 seconds <==== 
-------------------
DECRYPT JSON FIELDS COMPRESSED
-------------------
address: addr
publicKey: 3059301306072a8648ce3d020106082a8648ce3d0301070342000445b9f869f288cccb2f07e49fb4e3a776219a02c637b52201628ce98274edc8221b6c562d4ccf19d0aa1f777edae115e43e8e48af1c3b8649b8b0abe3a9edade4
timestamp: 1549976870
type: 1
signature: 304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf
emitter signature: 304502201f91cab95caa5443c7c57e884c80c1a69c8adcf22d30e22a84b4b14d6535f0ad022100dd2ed95806af1ae5661e56e2c0b657c4362656e2e68837b3e9a3fae21be5cbaf
====> Decryption took 0.001326 seconds <==== 
```