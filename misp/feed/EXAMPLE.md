# https://www.circl.lu/doc/misp/feed-osint/0b988513-9535-42f0-9ebc-5d6aec2e1c79.json
{
  "Event": {
    "uuid": "0b988513-9535-42f0-9ebc-5d6aec2e1c79",
    "timestamp": "1607324075",
    "analysis": "2",
    "date": "2020-11-27",
    "info": "OSINT - Egregor: The New Ransomware Variant To Watch",
    "threat_level_id": "1",
    "published": true,
    "extends_uuid": "",
    "publish_timestamp": "1607324084",
    "Orgc": {
      "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f",
      "name": "CIRCL"
    },
    "Tag": [
      {
        "colour": "#004646",
        "name": "type:OSINT"
      },
      {
        "colour": "#0071c3",
        "name": "osint:lifetime=\"perpetual\""
      },
      {
        "colour": "#0087e8",
        "name": "osint:certainty=\"50\""
      },
      {
        "colour": "#ffffff",
        "name": "tlp:white"
      },
      {
        "colour": "#0088cc",
        "name": "misp-galaxy:ransomware=\"Egregor\""
      }
    ],
    "Attribute": [
      {
        "uuid": "7df62701-db13-41e4-987c-dcd58b98b7c5",
        "value": "http://49.12.104.241:81/78.bin",
        "timestamp": "1606485600",
        "type": "url",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Network activity",
        "deleted": false
      },
      {
        "uuid": "6b2c6a04-37bd-4796-a56a-29489fd91efc",
        "value": "http://49.12.104.241/sm.dll",
        "timestamp": "1606485600",
        "type": "url",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Network activity",
        "deleted": false
      },
      {
        "uuid": "2cfaa8fd-5000-482c-a7f4-572982427af9",
        "value": "http://49.12.104.241:81/sm.dll",
        "timestamp": "1606485600",
        "type": "url",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Network activity",
        "deleted": false
      },
      {
        "uuid": "3c4fad3b-e2bd-4fad-a1e9-41da1d9c6b0e",
        "value": "91.199.212.52",
        "timestamp": "1607324075",
        "type": "ip-dst",
        "to_ids": false,
        "comment": "Potential false-positive but included in the OSINT report from digital shadows",
        "disable_correlation": false,
        "category": "Network activity",
        "deleted": false
      },
      {
        "uuid": "34b96233-8ea0-49e3-b93b-c776c87289d8",
        "value": "49.12.104.241",
        "timestamp": "1606485616",
        "type": "ip-dst",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Network activity",
        "deleted": false
      },
      {
        "uuid": "2d6a985c-63ee-47cd-af17-c47838f683c5",
        "value": "03cdec4a0a63a016d0767650cdaf1d4d24669795",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "a2b9348a-0583-4d17-bb56-2dc163f74640",
        "value": "069ef8443df750e9f72ebe4ed93c3e472a2396e2",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "b43e9989-0619-41dc-9518-847de4c3cf1d",
        "value": "072ab57f9db16d9fb92009c8e10b176bd4a2eff01c3bc6e190020cf5a0055505",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "63db7428-7fd6-4f8a-8ee0-e8bbaafc6f10",
        "value": "07d4bcb5b969a01fb21dc28e5cb1b7ceb05f2912",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "99e529ab-f8ed-4034-9c5f-9c7dcdc5f9ce",
        "value": "16a9c2917577e732cd6630b08e248443",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "aa877972-d255-4035-808a-7ff7077e69cf",
        "value": "1a722cde21a4338b26bc37401ef963022d97cea141c985e6615a10287f8d02ff",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "56d28b21-d88c-4d66-a7e7-ec55fbe52b6d",
        "value": "1cce0c0d67fe7f51f335a12138698403",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "9bb64496-b303-420f-8023-42e203e1c0fd",
        "value": "28f3f5a3ea270d9b896fe38b9df79a6ca430f5edab0423b3d834cf8d586f13e6",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "e73fecb3-c461-4486-a046-a38817e490db",
        "value": "2d01c32d51e4bbb986255e402da4624a61b8ae960532fbb7bb0d3b0080cb9946",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "7a27a35f-5b12-40d4-a23e-b0f8ee5d47d0",
        "value": "386cf4e151bc7510c3333eb1a5c96ab1b7becd8cfb94bcb76e93458078daf66f",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "6f7dc741-6908-4bbe-b68d-9c212883603c",
        "value": "3dba9fbef8f8a42ecfa65022b8a3c54738d15ef67c666272078b58b3c9a0a414",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "de3ad96b-b2ae-4137-a6b5-2c7a576c13fd",
        "value": "410afc5daebd7b39410b046286b814bb5fb5f9139167cd310bc59cc4461d4083",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "ca533984-24e2-4400-a1cd-b5716041c5b9",
        "value": "43445fbe21cf3512724646a284d3e5d7",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "04379602-bb89-47f3-9611-e69ea2628e9c",
        "value": "49b3d9c3bd6b6a13f89f0e849d80531454cc5cd259cbb7c8a806c67cd403575e",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "3dbe056f-c1d3-4abe-9e87-6e8aa0d4b184",
        "value": "4c36c3533a283e1aa199f80e20d264b9",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "c1f4ba97-9e4a-4e9c-8156-a21b0823a6cf",
        "value": "5455d104e693445dce5567236f4e047617bae7f09d5ca8699a838c2d17d37fb3",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "c1e0cc56-186c-4d53-8fe9-f81025d50219",
        "value": "561092877e91f2741ed061cbe7a57d1af552b600c6654ccc588cb6bff7939152",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "e1a88a7b-2c42-4397-8443-676d3dc71b40",
        "value": "5f9fcbdf7ad86583eb2bbcaa5741d88a",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "85265961-c86f-4052-a55e-0150811bf9de",
        "value": "605c2047be7c4a17823ad1fa5c1f94fd105721fce3621dc9148cd3baf352938e",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "1c1689d8-c42a-4ae2-9377-1a8d633bc39e",
        "value": "627c2219a80245a25e4fe9843ac2a021",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "12c55add-294a-450c-b0b5-b59f071a5a9f",
        "value": "65c320bc5258d8fa86aa9ffd876291d3",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "2ca0e677-f839-425b-90b1-e31d5312e5c3",
        "value": "7222c8acc69a7598989c335d528b366f801a41b434cbf928c6aef01f8e54f57a",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "fd9b5def-27a6-449e-a369-552df16fce6e",
        "value": "7bc6c2d714e88659b26b6b8ed6681b1f91eef6af",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "edff46c4-ab68-49ef-81b4-5d8c52c50386",
        "value": "7caed5f406445c788543f55af6d98a8bc4f0c104e6a51e2564dd37b6a485cc18",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "ba1e3664-8d83-46d9-aa3c-8f4ea9d58998",
        "value": "7dd1a1a0eefc5a653a30010f475cc37c",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "1623da53-514f-46be-974f-a0e548515571",
        "value": "9fffabede0ef679970666f04184340437cd70bc8fe870ee8174713ececf32398",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "b6bbf98a-ad0f-442c-bd3e-0993a05fea30",
        "value": "a654b3a37c27810db180822b72ad6d3e",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "a7eb918b-293f-4a6e-9e3c-89fcaabbe1c3",
        "value": "ac634854448eb8fcd3abf49c8f37cd21f4282dde",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "ee1c23b7-5995-4c14-b18f-b5633a3803fe",
        "value": "b027467332243c8186e59f68ff7c43c9e212d9e5074fedf003febcfedad4381a",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "10220945-92cc-4580-b33e-b6ddf267ac5d",
        "value": "b554791b5b161c34b0a7d26e34a88e60",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "e5ae581b-a5bd-4f9a-9ed2-231cb3882d9b",
        "value": "b81d2293b43decd5a401487da952deb32cbb53f118882b97b457a14c67029247",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "9cddc7e5-7fd1-4f7f-ba8a-8e82b6ae975f",
        "value": "b9dcee839437a917dde60eff9b6014b1",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "0e61d4aa-4ab5-4c0a-8771-c11ac0aa3d34",
        "value": "bd8c52bb1f5c034f11f3048e2ed89b7b8ff39261",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "ea0e4f9e-538f-44db-a026-0377bf60ceeb",
        "value": "c1c4e677b36a2ee6ae858546e727e73cc38c95c9024c724f939178b3c03de906",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "9f78fecb-07c6-405d-a871-7d25948e7f72",
        "value": "c9d46c319ed01c183598f7b9a60b9bca34b2eea989f4659e9aa27c7a1bf8681c",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "cd5ba297-ab8b-41e7-997c-0232b1d4e7be",
        "value": "d2d9484276a208641517a2273d96f34de1394b8e",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "cc4edef1-45d0-4331-9746-db247c9571e8",
        "value": "d6fa64f36eab990669f0b81f84b9a78a",
        "timestamp": "1606485659",
        "type": "md5",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "d63fdcc7-6974-4415-9cf8-579dac946fc7",
        "value": "e0caae0804957c5e31c53dd320ca83a5465169c9",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "c5d74096-dc54-48c6-810d-a1a685823c26",
        "value": "e27725074f7bc55014885921b7ec8b5319b1ef8f",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "a76afdc5-b2d4-4034-a293-e2e5645c09a1",
        "value": "e3ef50749f144bfd7f5d7d51aaa9e2332b706c4d8ac130fdc95f50662525f6e0",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "c9eb601a-3eb7-4002-b2a4-0b0b20b045a2",
        "value": "ed5b60a640a19afe8d1281bf691f40bac34eba8a",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "3aed8153-b054-4023-8d85-7e46fa25a1a5",
        "value": "f0215aac7be36a5fedeea51d34d8f8da2e98bf1b",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "b98abbfd-03e3-450c-a724-3b6774848758",
        "value": "f1ba626b8181bd1cd84f47f70838d9fa4d8117fac3bd07cbd73cb6f73b1297f8",
        "timestamp": "1606485659",
        "type": "sha256",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "e713ad5c-15c1-474b-a64e-8cad2d2d601d",
        "value": "f73e31d11f462f522a883c8f8f06d44f8d3e2f01",
        "timestamp": "1606485659",
        "type": "sha1",
        "to_ids": true,
        "comment": "",
        "disable_correlation": false,
        "category": "Payload delivery",
        "deleted": false
      },
      {
        "uuid": "749069e0-2af6-4912-b6af-fcbf036abc6b",
        "value": "https://www.digitalshadows.com/blog-and-research/egregor-the-new-ransomware-variant-to-watch/",
        "timestamp": "1606485863",
        "type": "link",
        "to_ids": false,
        "comment": "",
        "disable_correlation": false,
        "category": "External analysis",
        "deleted": false
      }
    ],
    "Object": [
      {
        "uuid": "dae954bf-d717-4db4-9f5c-975c7db3f90e",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "96054598-7232-45d3-bce7-214a97db1476",
            "timestamp": "0",
            "referenced_uuid": "9213f424-626b-40e0-b562-a7f7bc88e3a8",
            "object_uuid": "dae954bf-d717-4db4-9f5c-975c7db3f90e",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "1f9bdf8c-c428-456b-a877-b91aa11ee3c9",
            "value": "d6fa64f36eab990669f0b81f84b9a78a",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "a2d24c20-fff2-44da-9710-754939bfef1b",
            "value": "ed5b60a640a19afe8d1281bf691f40bac34eba8a",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "c5231610-2865-4c9f-ab7a-471b5bf506ee",
            "value": "9c900078cc6061fb7ba038ee5c065a45112665f214361d433fc3906bf288e0eb",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "9213f424-626b-40e0-b562-a7f7bc88e3a8",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "dc5f8db2-b8fe-438c-9205-d957b54da23c",
            "value": "2020-11-27T01:00:50+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "6f84c793-0767-4c5c-85d0-0b6642f9743b",
            "value": "https://www.virustotal.com/gui/file/9c900078cc6061fb7ba038ee5c065a45112665f214361d433fc3906bf288e0eb/detection/f-9c900078cc6061fb7ba038ee5c065a45112665f214361d433fc3906bf288e0eb-1606438850",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "9d87bdd7-4495-47bf-a905-47c84b608daf",
            "value": "59/69",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "dd11f943-da32-4ad3-b3ec-2eec523934cb",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "d325d115-70fa-4490-8b70-ff638f95b6f7",
            "timestamp": "0",
            "referenced_uuid": "007949e3-cb32-497a-816c-36cab32d9ac2",
            "object_uuid": "dd11f943-da32-4ad3-b3ec-2eec523934cb",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "103d0ef4-f52b-42e6-9ec4-e00a8dc0324e",
            "value": "65c320bc5258d8fa86aa9ffd876291d3",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "85e95421-8976-4f7f-ae59-030f6daf229a",
            "value": "f0215aac7be36a5fedeea51d34d8f8da2e98bf1b",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "06514ee7-4572-43b3-8222-35f0584f1b73",
            "value": "3fd510a3b2e0b0802d57cd5b1cac1e61797d50a08b87d9b5243becd9e2f7073f",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "007949e3-cb32-497a-816c-36cab32d9ac2",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "882fb960-a758-4fbf-a75b-b5e267d396d3",
            "value": "2020-11-25T22:01:30+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "d0f5f44d-9683-4312-a0bd-d307576d6a52",
            "value": "https://www.virustotal.com/gui/file/3fd510a3b2e0b0802d57cd5b1cac1e61797d50a08b87d9b5243becd9e2f7073f/detection/f-3fd510a3b2e0b0802d57cd5b1cac1e61797d50a08b87d9b5243becd9e2f7073f-1606341690",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "5b423520-1cd8-4acf-a27a-4d86ca35ed40",
            "value": "60/69",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "bcf8042f-0b95-4178-a074-45aac53a7c61",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "5a7ec59a-d627-4307-9c15-de919379fb6b",
            "timestamp": "0",
            "referenced_uuid": "23893bf9-d6af-4f9a-a771-0c5da6ea7a07",
            "object_uuid": "bcf8042f-0b95-4178-a074-45aac53a7c61",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "811ad902-6503-4c2e-b3e3-13afa7e2a6e9",
            "value": "b554791b5b161c34b0a7d26e34a88e60",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "3c52f807-f076-46b8-9acd-4ef8bce73717",
            "value": "ac634854448eb8fcd3abf49c8f37cd21f4282dde",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "2f2aebe2-934d-408d-97a1-b385b20ebb02",
            "value": "7caed5f406445c788543f55af6d98a8bc4f0c104e6a51e2564dd37b6a485cc18",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "23893bf9-d6af-4f9a-a771-0c5da6ea7a07",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "1df043c0-799a-4b82-92cc-ec054e280629",
            "value": "2020-11-16T15:54:19+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "eb2437fb-3f41-4d3a-bbde-64068f9014e0",
            "value": "https://www.virustotal.com/gui/file/7caed5f406445c788543f55af6d98a8bc4f0c104e6a51e2564dd37b6a485cc18/detection/f-7caed5f406445c788543f55af6d98a8bc4f0c104e6a51e2564dd37b6a485cc18-1605542059",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "be03b5ad-b229-4c57-b428-0c1ea667af8c",
            "value": "54/71",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "65e672fd-bda4-421a-b845-8ae2187d3a84",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "bff28b1c-b58d-4a0e-b225-af9631d93303",
            "timestamp": "0",
            "referenced_uuid": "9ddcd362-1434-4c87-bc0b-3fb2518d1df4",
            "object_uuid": "65e672fd-bda4-421a-b845-8ae2187d3a84",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "a8460459-6479-486d-a13b-05994e27e236",
            "value": "7dd1a1a0eefc5a653a30010f475cc37c",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "9d8c92f1-f8ec-41ce-8c1a-468c8cbb675f",
            "value": "e27725074f7bc55014885921b7ec8b5319b1ef8f",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "52e39986-59a4-4cf1-a3f1-eebf55490a07",
            "value": "92d72d4c1aaef1983a05bb65ee540236b98fdab4ca382d15a845ab6d07ea1fb8",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "9ddcd362-1434-4c87-bc0b-3fb2518d1df4",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "6362a09a-008d-421a-9bc9-d4f6d099b97a",
            "value": "2020-11-27T00:58:35+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "c9b93f8b-09bf-4dcf-bff5-88347b555789",
            "value": "https://www.virustotal.com/gui/file/92d72d4c1aaef1983a05bb65ee540236b98fdab4ca382d15a845ab6d07ea1fb8/detection/f-92d72d4c1aaef1983a05bb65ee540236b98fdab4ca382d15a845ab6d07ea1fb8-1606438715",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "8ed065ee-fd3a-4af4-aaf9-43d6552a44f6",
            "value": "53/70",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "9d66db92-9270-452b-8b61-809f87430946",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "7e1cc4be-4ce8-449b-883b-429d6985e09e",
            "timestamp": "0",
            "referenced_uuid": "4ec1d2b7-780e-44b4-8b93-5e1eb233ee3c",
            "object_uuid": "9d66db92-9270-452b-8b61-809f87430946",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "e832269b-73d4-40f5-a43b-dbce62c67158",
            "value": "627c2219a80245a25e4fe9843ac2a021",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "b1840fe6-aa48-410f-90ad-055dc5a5d604",
            "value": "e0caae0804957c5e31c53dd320ca83a5465169c9",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "d577c969-d63e-4d47-b25a-f058e59190e9",
            "value": "967422de1acc14deb7e7ce803d86aff44e2652bfcd550e3a34c2e37abc883dee",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "4ec1d2b7-780e-44b4-8b93-5e1eb233ee3c",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "bd3490a4-e177-4a51-8d9f-6a30201c059b",
            "value": "2020-11-16T16:43:10+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "76181a61-f2b3-4b75-9741-34e31ceeacdc",
            "value": "https://www.virustotal.com/gui/file/967422de1acc14deb7e7ce803d86aff44e2652bfcd550e3a34c2e37abc883dee/detection/f-967422de1acc14deb7e7ce803d86aff44e2652bfcd550e3a34c2e37abc883dee-1605544990",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "46a5162e-46d8-417c-b4b2-77380d488741",
            "value": "54/71",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "df122a7d-f66d-4cb2-8d33-dcb1a26a7631",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "2352145b-0090-4dee-b996-b231f897d18d",
            "timestamp": "0",
            "referenced_uuid": "75f5a863-d2ad-4b75-aed3-57824e1f4b74",
            "object_uuid": "df122a7d-f66d-4cb2-8d33-dcb1a26a7631",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "1eb3321f-f547-4862-8612-368b3bdef296",
            "value": "a654b3a37c27810db180822b72ad6d3e",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "a75920ec-f14c-4df0-b3c0-57f1a25b3b7b",
            "value": "d2d9484276a208641517a2273d96f34de1394b8e",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "939c0e28-a167-4d3f-b29f-4ebdce80f974",
            "value": "4c9e3ffda0e663217638e6192a093bbc23cd9ebfbdf6d2fc683f331beaee0321",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "75f5a863-d2ad-4b75-aed3-57824e1f4b74",
        "timestamp": "1606486058",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "2515a56b-a668-4796-97b6-3a7630f44182",
            "value": "2020-11-25T14:20:14+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "0efc54c6-5cf5-48b4-8dd7-5e9e552732a4",
            "value": "https://www.virustotal.com/gui/file/4c9e3ffda0e663217638e6192a093bbc23cd9ebfbdf6d2fc683f331beaee0321/detection/f-4c9e3ffda0e663217638e6192a093bbc23cd9ebfbdf6d2fc683f331beaee0321-1606314014",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "2a028bef-1056-4588-bf1f-cb5d4a44f839",
            "value": "58/70",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "0e69334e-7f89-4134-93ff-8a78125e76a1",
        "timestamp": "1606486058",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "56795001-a0fc-4046-9f20-4afeda719220",
            "timestamp": "0",
            "referenced_uuid": "f5e9e59f-786a-4061-b160-275c77ad1413",
            "object_uuid": "0e69334e-7f89-4134-93ff-8a78125e76a1",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "d7707cb8-3e9b-4644-81b8-4fa4ed945843",
            "value": "1cce0c0d67fe7f51f335a12138698403",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "3286f520-2a9b-4aa9-9d39-ee0756b4f282",
            "value": "7bc6c2d714e88659b26b6b8ed6681b1f91eef6af",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "8e3ad482-9f9c-48fd-9899-bddb20e6b95d",
            "value": "c1c4e677b36a2ee6ae858546e727e73cc38c95c9024c724f939178b3c03de906",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "f5e9e59f-786a-4061-b160-275c77ad1413",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "970bc5bc-93d6-4270-a418-4a303c079dba",
            "value": "2020-11-16T16:01:40+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "a0b0ffe8-0444-4d2c-bcda-37baf22dda00",
            "value": "https://www.virustotal.com/gui/file/c1c4e677b36a2ee6ae858546e727e73cc38c95c9024c724f939178b3c03de906/detection/f-c1c4e677b36a2ee6ae858546e727e73cc38c95c9024c724f939178b3c03de906-1605542500",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "629cced7-8099-466d-994e-a2f8d59f7ee3",
            "value": "57/70",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "3accfc2d-699d-4b38-b73b-7f44f6178f86",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "945b4c4e-a49b-4b85-bcfa-1bd0c6b271d2",
            "timestamp": "0",
            "referenced_uuid": "de4cb21f-0c76-4ba7-b6d0-d7bab2efb9fe",
            "object_uuid": "3accfc2d-699d-4b38-b73b-7f44f6178f86",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "b8eeaf38-3682-497f-93f3-9300537496a7",
            "value": "16a9c2917577e732cd6630b08e248443",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "2823c52f-6fb2-4435-9c07-39675e3321a4",
            "value": "bd8c52bb1f5c034f11f3048e2ed89b7b8ff39261",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "16a69999-fbd2-4711-9a65-d802ac60e344",
            "value": "a376fd507afe8a1b5d377d18436e5701702109ac9d3e7026d19b65a7d313b332",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "de4cb21f-0c76-4ba7-b6d0-d7bab2efb9fe",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "ef8905e9-851d-4c1a-96ea-fc208d4b3210",
            "value": "2020-11-16T15:53:21+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "548de872-7764-4119-b2bb-9b9452de2139",
            "value": "https://www.virustotal.com/gui/file/a376fd507afe8a1b5d377d18436e5701702109ac9d3e7026d19b65a7d313b332/detection/f-a376fd507afe8a1b5d377d18436e5701702109ac9d3e7026d19b65a7d313b332-1605542001",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "7a1386fb-e2b4-4a77-8c5f-9296be1f3dab",
            "value": "61/71",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "1869f991-c37b-421f-8acf-0ef897b222c1",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "f3366f96-5a53-456d-8138-cadfa7b73757",
            "timestamp": "0",
            "referenced_uuid": "c1cc2a52-510b-43c3-84c3-22ed9fc3b584",
            "object_uuid": "1869f991-c37b-421f-8acf-0ef897b222c1",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "96dce908-b269-4877-8af8-c086716e7b10",
            "value": "4c36c3533a283e1aa199f80e20d264b9",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "fda3940c-b8b1-485a-abd7-dcfca63dc631",
            "value": "f73e31d11f462f522a883c8f8f06d44f8d3e2f01",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "0875c745-89b4-4bbe-8a9c-12e74a89df75",
            "value": "aee131ba1bfc4b6fa1961a7336e43d667086ebd2c7ff81029e14b2bf47d9f3a7",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "c1cc2a52-510b-43c3-84c3-22ed9fc3b584",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "8ee76fa2-920d-440b-bdc2-3fc30af0754b",
            "value": "2020-11-27T08:07:02+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "e9f54c39-673d-466c-9b04-eaa3c79889db",
            "value": "https://www.virustotal.com/gui/file/aee131ba1bfc4b6fa1961a7336e43d667086ebd2c7ff81029e14b2bf47d9f3a7/detection/f-aee131ba1bfc4b6fa1961a7336e43d667086ebd2c7ff81029e14b2bf47d9f3a7-1606464422",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "6fee5a39-f474-44ec-b82a-090e6cb554b5",
            "value": "55/67",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "14e45266-3407-488f-bf65-a3db1d80eaab",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "a961d292-dd6d-440d-8949-67116c9916d2",
            "timestamp": "0",
            "referenced_uuid": "67931bd5-bd64-4653-a4f2-69c943ddde2b",
            "object_uuid": "14e45266-3407-488f-bf65-a3db1d80eaab",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "d464cab5-d469-4a8d-9ed7-a27d14c0ed7f",
            "value": "5f9fcbdf7ad86583eb2bbcaa5741d88a",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "8041a3c7-593b-4c1f-838f-893d3113c9db",
            "value": "03cdec4a0a63a016d0767650cdaf1d4d24669795",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "02b83c9e-5b85-4a40-abf1-af4105c874fd",
            "value": "004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "67931bd5-bd64-4653-a4f2-69c943ddde2b",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "435c62af-58c8-49b7-b288-013ca41a4d19",
            "value": "2020-11-25T22:01:34+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "adfa8063-bf47-421e-91f0-651a138fd5ca",
            "value": "https://www.virustotal.com/gui/file/004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a/detection/f-004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a-1606341694",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "0f674ac5-00ba-4041-86d3-ed87e938a86e",
            "value": "58/69",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "ba465669-584e-4428-b1bc-8a8e56072fa4",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "1c312bb0-463b-4a8e-9aa3-6fbfc5148800",
            "timestamp": "0",
            "referenced_uuid": "13b55e21-1bec-4e2a-9d27-0d28b919434f",
            "object_uuid": "ba465669-584e-4428-b1bc-8a8e56072fa4",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "68966d05-2301-4c6a-8dfa-695534dd40b9",
            "value": "43445fbe21cf3512724646a284d3e5d7",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "69015fee-fdf5-4fbc-9d64-74dc6f52a6ce",
            "value": "07d4bcb5b969a01fb21dc28e5cb1b7ceb05f2912",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "4991ed9e-9b48-49f7-a0a0-8e588618e96d",
            "value": "28f3f5a3ea270d9b896fe38b9df79a6ca430f5edab0423b3d834cf8d586f13e6",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "13b55e21-1bec-4e2a-9d27-0d28b919434f",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "1f419ed7-d663-4fcf-aecc-6cddb6a453a3",
            "value": "2020-11-25T14:19:11+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "475f57d4-31f1-48d2-8a6f-c0f63532b18a",
            "value": "https://www.virustotal.com/gui/file/28f3f5a3ea270d9b896fe38b9df79a6ca430f5edab0423b3d834cf8d586f13e6/detection/f-28f3f5a3ea270d9b896fe38b9df79a6ca430f5edab0423b3d834cf8d586f13e6-1606313951",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "54a02634-b414-40fd-ba4d-5acd8f83a222",
            "value": "56/69",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "17583e77-74e5-4ade-a66f-db2e20e483d4",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "8cb1e975-9145-4343-8383-e30695e8a85a",
            "timestamp": "0",
            "referenced_uuid": "988ecb34-22bb-4c5e-869a-db3c44e73de7",
            "object_uuid": "17583e77-74e5-4ade-a66f-db2e20e483d4",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "eaee000e-8d29-49d0-aea3-c60208c1357f",
            "value": "b9dcee839437a917dde60eff9b6014b1",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "be1a8ca0-da38-4e73-bd63-97934d2bb46a",
            "value": "069ef8443df750e9f72ebe4ed93c3e472a2396e2",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "169f55f4-45c5-4ffb-a4fd-ebe0e70cc958",
            "value": "2d01c32d51e4bbb986255e402da4624a61b8ae960532fbb7bb0d3b0080cb9946",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "988ecb34-22bb-4c5e-869a-db3c44e73de7",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "dbbc0ea0-2f65-47b4-8ee4-dd8785e70a3c",
            "value": "2020-11-16T16:01:02+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "6ecb327f-7fa5-4650-840d-1315545b1712",
            "value": "https://www.virustotal.com/gui/file/2d01c32d51e4bbb986255e402da4624a61b8ae960532fbb7bb0d3b0080cb9946/detection/f-2d01c32d51e4bbb986255e402da4624a61b8ae960532fbb7bb0d3b0080cb9946-1605542462",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "592441af-375c-4e9b-bfdc-0f1c3b486806",
            "value": "57/70",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "b44424f8-91b4-490d-8500-efacd8a13cfb",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "99d031f8-e534-4d67-8d2e-ccf2aa143c5a",
            "timestamp": "0",
            "referenced_uuid": "2f3790f6-642c-403c-8431-6c9701b6167b",
            "object_uuid": "b44424f8-91b4-490d-8500-efacd8a13cfb",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "e1e9bb9e-66e1-4eb6-8c15-d0ec11167fb7",
            "value": "72d118b8e7560cc99c894d985d2c2978",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "dc8b236c-b6b6-4e89-a7cf-3838b6b3fb34",
            "value": "3fd4783920dac610052c9e135cd52b81d3876c6b",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "ee3a3199-cf1c-48d5-aff7-ff8228206232",
            "value": "f1ba626b8181bd1cd84f47f70838d9fa4d8117fac3bd07cbd73cb6f73b1297f8",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "2f3790f6-642c-403c-8431-6c9701b6167b",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "adcad2ff-523b-4992-847b-e98a02337174",
            "value": "2020-11-27T01:05:07+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "42e3f766-eea7-4488-940c-a5b2e2fb3bb1",
            "value": "https://www.virustotal.com/gui/file/f1ba626b8181bd1cd84f47f70838d9fa4d8117fac3bd07cbd73cb6f73b1297f8/detection/f-f1ba626b8181bd1cd84f47f70838d9fa4d8117fac3bd07cbd73cb6f73b1297f8-1606439107",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "6a3b72b9-3753-4a2c-b64a-d89c109c06f7",
            "value": "37/69",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "e5a467d0-1e18-4cae-a708-15ca3d14f9b4",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "480996f3-a1e0-4047-a86f-d6b71dc257c7",
            "timestamp": "0",
            "referenced_uuid": "7958e8a6-e292-4740-81ca-eb75a9a47d47",
            "object_uuid": "e5a467d0-1e18-4cae-a708-15ca3d14f9b4",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "46da9a40-d7b2-486f-9536-3a989954baa1",
            "value": "9f71f74c9febf27d3c71d4593856565a",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "b43cc573-61e1-474a-b762-28ae4ed73256",
            "value": "818bc5112671077a2fc2cde130a1d9d310f68913",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "b0be7dcc-0cf2-4528-a2d5-948f743f6434",
            "value": "e3ef50749f144bfd7f5d7d51aaa9e2332b706c4d8ac130fdc95f50662525f6e0",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "7958e8a6-e292-4740-81ca-eb75a9a47d47",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "ba3ec290-5b7e-41e3-b45f-dc0654ba5e2f",
            "value": "2020-11-27T08:07:28+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "b7dea80e-7692-4074-8a7f-579a27717ad6",
            "value": "https://www.virustotal.com/gui/file/e3ef50749f144bfd7f5d7d51aaa9e2332b706c4d8ac130fdc95f50662525f6e0/detection/f-e3ef50749f144bfd7f5d7d51aaa9e2332b706c4d8ac130fdc95f50662525f6e0-1606464448",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "1e26cfad-3563-407e-98ce-2e4b19a0d17c",
            "value": "0/60",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "47ab1fff-99b1-4a8f-ac26-2fdcdabf26fe",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "e841ae32-6d88-4eb1-8faa-e9c21f1bf39e",
            "timestamp": "0",
            "referenced_uuid": "09ceb2d2-eb7e-4a16-bc57-29afde1aeeed",
            "object_uuid": "47ab1fff-99b1-4a8f-ac26-2fdcdabf26fe",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "f2397afd-2216-431e-9bdb-3acad6940734",
            "value": "6a04bfcc5465b0164eed89b28f61a787",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "77839512-7f60-4965-9274-07f13010c1ce",
            "value": "6b32973458045540fd6482bcb2e16dcd718485c9",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "7d3b52c1-8ec6-495f-adea-40fc25111265",
            "value": "9fffabede0ef679970666f04184340437cd70bc8fe870ee8174713ececf32398",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "09ceb2d2-eb7e-4a16-bc57-29afde1aeeed",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "cfba3358-0d04-4db5-9b60-262c0d33fc14",
            "value": "2020-11-16T15:46:40+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "460dc333-dd24-45a4-a71b-ec890a3afcc1",
            "value": "https://www.virustotal.com/gui/file/9fffabede0ef679970666f04184340437cd70bc8fe870ee8174713ececf32398/detection/f-9fffabede0ef679970666f04184340437cd70bc8fe870ee8174713ececf32398-1605541600",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "d7054b2b-6a0d-4a15-a9a9-7153b83ef5e5",
            "value": "48/65",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "9510dcf9-150b-41e5-b913-e36a1547e4a1",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "c2749406-6c33-4e19-9d99-4967fcb993ba",
            "timestamp": "0",
            "referenced_uuid": "e8981eda-4685-4231-b3ea-5188b9c16ead",
            "object_uuid": "9510dcf9-150b-41e5-b913-e36a1547e4a1",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "b888b8a8-c596-44f5-a605-aef45dc1d47f",
            "value": "53d183302b3933b7338e1ce00d893ece",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "c62b5023-220f-4310-846f-17812abe85e7",
            "value": "51ba154f3227eac229e4c1709333d0053655fb1c",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "74237af3-df9c-4220-bf9b-ef12f9100dd2",
            "value": "410afc5daebd7b39410b046286b814bb5fb5f9139167cd310bc59cc4461d4083",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "e8981eda-4685-4231-b3ea-5188b9c16ead",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "b661a57c-8518-40fe-b4e0-89f937ae816a",
            "value": "2020-11-27T08:07:23+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "80446004-61a1-4779-aa25-5758191792a5",
            "value": "https://www.virustotal.com/gui/file/410afc5daebd7b39410b046286b814bb5fb5f9139167cd310bc59cc4461d4083/detection/f-410afc5daebd7b39410b046286b814bb5fb5f9139167cd310bc59cc4461d4083-1606464443",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "08d09adf-83de-483d-aacb-8728cafffe03",
            "value": "0/60",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "19b4a708-3497-486e-883d-02bc6e796e06",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "420d2a5b-39d8-44b1-a83c-db361c3308df",
            "timestamp": "0",
            "referenced_uuid": "79a5210a-c48a-4e64-bfae-a504be65114c",
            "object_uuid": "19b4a708-3497-486e-883d-02bc6e796e06",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "0698f4f2-c696-4dad-b73f-bc879a821aa1",
            "value": "c2b848832283e7b8d8f72909da729bc0",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "ddc8d138-93d7-491b-b384-acee8cc49702",
            "value": "013f1f3f2a306f3f0f94b48f949325a70a997746",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "b2b57218-4c4c-41f5-80a0-4b624488da17",
            "value": "c9d46c319ed01c183598f7b9a60b9bca34b2eea989f4659e9aa27c7a1bf8681c",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "79a5210a-c48a-4e64-bfae-a504be65114c",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "ff8a2b0b-7899-4b6b-9108-0ce2840af188",
            "value": "2020-11-16T15:46:43+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "b4c7c0fc-6302-4a50-9b63-f6c4d0d96f3d",
            "value": "https://www.virustotal.com/gui/file/c9d46c319ed01c183598f7b9a60b9bca34b2eea989f4659e9aa27c7a1bf8681c/detection/f-c9d46c319ed01c183598f7b9a60b9bca34b2eea989f4659e9aa27c7a1bf8681c-1605541603",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "54bc1843-6dfb-4b04-884a-5310e9c7e93e",
            "value": "48/67",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "c25cbed6-51cb-4031-b4a9-b2c022c819b6",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "97f8f12a-036b-4bcf-9bc4-fe18758d5e9a",
            "timestamp": "0",
            "referenced_uuid": "d74f7fc9-73c8-418e-861c-deb6e2078070",
            "object_uuid": "c25cbed6-51cb-4031-b4a9-b2c022c819b6",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "e6f0df91-e3c8-4281-9e05-cb166562116c",
            "value": "49a6fb8ee6a08459a404b27f9e2b868b",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "91ad38e0-78ee-4ae6-8a0d-72dfe4776369",
            "value": "5da8a11917e18dbf81033f973c0a2f0d8854e43b",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "c01865c5-4967-4e47-b9aa-0e7911ddc3f0",
            "value": "7222c8acc69a7598989c335d528b366f801a41b434cbf928c6aef01f8e54f57a",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "d74f7fc9-73c8-418e-861c-deb6e2078070",
        "timestamp": "1606486059",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "de402bde-2bca-4c2a-8550-985a6f197f54",
            "value": "2020-11-27T00:56:57+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "655bdcb4-7ef1-4ec2-ad89-613df0e7ccf3",
            "value": "https://www.virustotal.com/gui/file/7222c8acc69a7598989c335d528b366f801a41b434cbf928c6aef01f8e54f57a/detection/f-7222c8acc69a7598989c335d528b366f801a41b434cbf928c6aef01f8e54f57a-1606438617",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "3efa3285-4fd7-4bbb-be3f-d5271acdfbe8",
            "value": "49/70",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "92080893-0f34-460d-8899-99f7cbd0d680",
        "timestamp": "1606486059",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "1fa74f3f-d208-490e-a566-f1a772f0f6e2",
            "timestamp": "0",
            "referenced_uuid": "a8540f6a-bf63-4f19-85e4-2af8bb931dd6",
            "object_uuid": "92080893-0f34-460d-8899-99f7cbd0d680",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "ff6e8d89-c5f3-45a8-b626-009623bb51a1",
            "value": "53c9924df26b5043f91352f59a9ffe9f",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "2db298ac-bbff-4261-bf39-02138b004947",
            "value": "aa2745c2d5ef7dbc239544c69b3e27193fa6049c",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "3942acac-7d5b-4294-9367-46fbf12c92f5",
            "value": "b027467332243c8186e59f68ff7c43c9e212d9e5074fedf003febcfedad4381a",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "a8540f6a-bf63-4f19-85e4-2af8bb931dd6",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "74987204-73e1-4dcd-a6ed-afc6d8eec16c",
            "value": "2020-11-14T20:11:56+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "50d56407-3f86-46e5-91d6-b312ad52bc22",
            "value": "https://www.virustotal.com/gui/file/b027467332243c8186e59f68ff7c43c9e212d9e5074fedf003febcfedad4381a/detection/f-b027467332243c8186e59f68ff7c43c9e212d9e5074fedf003febcfedad4381a-1605384716",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "63ae2a33-0a5a-4dbd-9e6e-e9f323602494",
            "value": "49/71",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "567cf864-68d7-48d6-a46c-f844eb6a6f88",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "42d95b6a-96e9-4a86-a1a7-ebeebe9da44e",
            "timestamp": "0",
            "referenced_uuid": "84145e3f-4739-4bfa-a8e0-bdb028d4bcea",
            "object_uuid": "567cf864-68d7-48d6-a46c-f844eb6a6f88",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "ee782349-7dc8-47af-8fbf-06a45f184ad7",
            "value": "1cca16fe0ccf7e856dba71c8959865ad",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "b10ac416-6860-4796-ab6f-897537476ecb",
            "value": "38d3658ec45e949623278a8174981d18174ea91a",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "fc78b645-6ebd-4425-abe7-d774df628c80",
            "value": "561092877e91f2741ed061cbe7a57d1af552b600c6654ccc588cb6bff7939152",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "84145e3f-4739-4bfa-a8e0-bdb028d4bcea",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "3186db81-6a10-4b53-9239-91a346e91dcb",
            "value": "2020-11-27T00:53:30+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "427a731a-96e2-4095-852e-756e0e00cc63",
            "value": "https://www.virustotal.com/gui/file/561092877e91f2741ed061cbe7a57d1af552b600c6654ccc588cb6bff7939152/detection/f-561092877e91f2741ed061cbe7a57d1af552b600c6654ccc588cb6bff7939152-1606438410",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "d4ee7871-1bc5-4194-9d99-8ed8a75a624b",
            "value": "50/66",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "6e8e34ab-431a-4d24-9765-cb70cab1a1d3",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "46f9ad9e-baeb-4189-b160-51023740ecfa",
            "timestamp": "0",
            "referenced_uuid": "46d36b17-64ff-4412-989f-acdd77c69394",
            "object_uuid": "6e8e34ab-431a-4d24-9765-cb70cab1a1d3",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "f4d878c1-bfde-4c4f-b7d6-f328a63380d8",
            "value": "59c474473874115c2e3e7b9bf5793b6b",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "cc3537e0-82da-488c-abca-fc7845666f95",
            "value": "26df23a4cbeca13cd298571f47cc5eb3d67c9bfd",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "f87aed43-dd5b-4e54-bedd-ff6a6146d7b1",
            "value": "386cf4e151bc7510c3333eb1a5c96ab1b7becd8cfb94bcb76e93458078daf66f",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "46d36b17-64ff-4412-989f-acdd77c69394",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "58948999-9481-4014-9d60-13c8bc6e34d4",
            "value": "2020-11-27T08:07:16+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "b09caaca-8233-4a2b-a56d-f7536c585041",
            "value": "https://www.virustotal.com/gui/file/386cf4e151bc7510c3333eb1a5c96ab1b7becd8cfb94bcb76e93458078daf66f/detection/f-386cf4e151bc7510c3333eb1a5c96ab1b7becd8cfb94bcb76e93458078daf66f-1606464436",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "ad848794-0b69-4809-a562-7a856da279bd",
            "value": "0/62",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "7d17c216-41bc-4d87-9a40-98a3b01d2bda",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "c5534a99-52d6-4423-8224-e8b1ce27b9ae",
            "timestamp": "0",
            "referenced_uuid": "5be430cb-a5f4-4d92-b5be-570b3cca50de",
            "object_uuid": "7d17c216-41bc-4d87-9a40-98a3b01d2bda",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "c6b754a7-e70a-4f37-9973-a1f60624dd00",
            "value": "a24ef21df2c942530fd41284c1773e6b",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "214ec222-8de3-4434-8072-0c6c4482d800",
            "value": "ae964ba3a50c4dd543472e1e9daea04696ffe51b",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "52f5bc2b-3a3e-49ec-9b8b-1121a5b85e83",
            "value": "5455d104e693445dce5567236f4e047617bae7f09d5ca8699a838c2d17d37fb3",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "5be430cb-a5f4-4d92-b5be-570b3cca50de",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "77b2912b-ca82-491c-8e33-0aee9610a2e2",
            "value": "2020-11-27T08:07:27+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "23f55415-548a-4b9d-b92e-4a4eaf0ff3d9",
            "value": "https://www.virustotal.com/gui/file/5455d104e693445dce5567236f4e047617bae7f09d5ca8699a838c2d17d37fb3/detection/f-5455d104e693445dce5567236f4e047617bae7f09d5ca8699a838c2d17d37fb3-1606464447",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "ea435c86-86db-476a-8813-32cd6b34fc65",
            "value": "0/60",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "046651a5-adf6-428a-9831-45f361bded36",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "1444730d-67de-4f68-ad31-2eef3f0261a2",
            "timestamp": "0",
            "referenced_uuid": "467a4633-96c9-4bb0-b34d-dbcee67a71df",
            "object_uuid": "046651a5-adf6-428a-9831-45f361bded36",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "746c21fc-a7b3-4de8-97e7-684198356aa4",
            "value": "1c268458ec2e4b3f93241eb7fa5dba22",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "36e1fc38-55d7-4ec7-9436-bfcbfa368a80",
            "value": "54efafa085ecbe46b09527664944536b99c7c599",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "9c25f3c1-bad9-4fa0-ba4d-8c45ceeabccd",
            "value": "072ab57f9db16d9fb92009c8e10b176bd4a2eff01c3bc6e190020cf5a0055505",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "467a4633-96c9-4bb0-b34d-dbcee67a71df",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "4443946c-94cb-4e5e-b4f3-1979b89a51fd",
            "value": "2020-11-16T15:46:37+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "58bbe409-70be-44d0-8335-8329cc10a228",
            "value": "https://www.virustotal.com/gui/file/072ab57f9db16d9fb92009c8e10b176bd4a2eff01c3bc6e190020cf5a0055505/detection/f-072ab57f9db16d9fb92009c8e10b176bd4a2eff01c3bc6e190020cf5a0055505-1605541597",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "46239134-41e1-4f34-ac6b-86c874b8d4fc",
            "value": "50/67",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "48c374dc-b8b4-40a7-b1e9-8f045d5ec4f3",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "a91b6b01-a3a3-418a-98a4-1aecd5959050",
            "timestamp": "0",
            "referenced_uuid": "0efde995-6a23-4e63-b99c-87b832578777",
            "object_uuid": "48c374dc-b8b4-40a7-b1e9-8f045d5ec4f3",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "5ab00c80-73a4-4a50-a75b-1f3b44b24f0e",
            "value": "afb142ddb812e8ac28c65d3923d67969",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "c1ab4f26-83f5-4bd6-b752-f8870f8d2a0c",
            "value": "cf4989c59e27b5c962488bbf118c47f78b471400",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "9bc212e3-6027-4204-b11b-2e59dfb4c675",
            "value": "3dba9fbef8f8a42ecfa65022b8a3c54738d15ef67c666272078b58b3c9a0a414",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "0efde995-6a23-4e63-b99c-87b832578777",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "d6cda59c-d35e-4891-afda-6bb63b64f309",
            "value": "2020-11-27T08:07:19+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "7ba7fa99-ff32-4a38-9d76-6d5a80ad1f60",
            "value": "https://www.virustotal.com/gui/file/3dba9fbef8f8a42ecfa65022b8a3c54738d15ef67c666272078b58b3c9a0a414/detection/f-3dba9fbef8f8a42ecfa65022b8a3c54738d15ef67c666272078b58b3c9a0a414-1606464439",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "f8e4bf65-0d03-4539-a2c2-90bf0478df35",
            "value": "0/57",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "8a270f9e-a320-44c9-9235-9b1501ec37f7",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "83ba0766-cebb-4925-986a-516a41be9f47",
            "timestamp": "0",
            "referenced_uuid": "8ce10412-621c-49e7-aca8-ed9fb81564a6",
            "object_uuid": "8a270f9e-a320-44c9-9235-9b1501ec37f7",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "910088b4-5705-4c59-8c88-fb8755bd723d",
            "value": "4858380a7ff04571f485785f9a80b24f",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "a5705259-e36b-4f65-ad73-4ec590c34bf0",
            "value": "47af78c65b319db497d54b1ba95c9a6d3d8e9235",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "f6aa6604-f0f3-44e8-a115-f35c4590827e",
            "value": "49b3d9c3bd6b6a13f89f0e849d80531454cc5cd259cbb7c8a806c67cd403575e",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "8ce10412-621c-49e7-aca8-ed9fb81564a6",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "e0ba4ae9-87d4-4ec9-b2dc-fb103cce9c3a",
            "value": "2020-11-27T08:07:25+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "0e2d8372-52f2-48fb-9d05-a0b9dac1ac05",
            "value": "https://www.virustotal.com/gui/file/49b3d9c3bd6b6a13f89f0e849d80531454cc5cd259cbb7c8a806c67cd403575e/detection/f-49b3d9c3bd6b6a13f89f0e849d80531454cc5cd259cbb7c8a806c67cd403575e-1606464445",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "8512edee-a2ce-47eb-b20c-3e78d7a1e7cd",
            "value": "0/60",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "ea980ee5-7614-4c42-9c8d-a2d7a628177b",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "2ad2e86e-36d4-444a-8091-1f27c92b833b",
            "timestamp": "0",
            "referenced_uuid": "cd62008b-bd96-4542-8e5f-9344d3250a48",
            "object_uuid": "ea980ee5-7614-4c42-9c8d-a2d7a628177b",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "967ba691-f6d8-491d-9189-c9d38cf8102d",
            "value": "1b116e0aed51c8d830e080b56a70bb37",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "d974a7e7-77a8-40cb-a6fc-58c3f5ef39fa",
            "value": "2ef7977e16ab287b1bade8cf74470bb69260f41d",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "42a36a24-ecf3-4abe-9b6c-f438565ffd51",
            "value": "1a722cde21a4338b26bc37401ef963022d97cea141c985e6615a10287f8d02ff",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "cd62008b-bd96-4542-8e5f-9344d3250a48",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "d03bed96-f676-473c-9a51-1da925b73151",
            "value": "2020-11-26T14:16:59+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "8712cf1e-2437-4c18-a15a-a6d12227fdd5",
            "value": "https://www.virustotal.com/gui/file/1a722cde21a4338b26bc37401ef963022d97cea141c985e6615a10287f8d02ff/detection/f-1a722cde21a4338b26bc37401ef963022d97cea141c985e6615a10287f8d02ff-1606400219",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "d6eb144f-87ab-4490-b7df-7929fde9f3f7",
            "value": "0/60",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "a28e00ce-b822-427e-b079-843a25ba6a20",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "976d469b-cd2a-4c3a-b9bd-cb325d5a2933",
            "timestamp": "0",
            "referenced_uuid": "528be816-9ed6-4704-8e72-1aeed9480cf2",
            "object_uuid": "a28e00ce-b822-427e-b079-843a25ba6a20",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "03aca6a9-664d-470d-8f72-42ee863df47b",
            "value": "1cc47a49ac4082cd78244ca46a8eef4d",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "7617905d-6354-47dd-bf8b-233bd316da7a",
            "value": "21e64bfccb226adcef4754213e29b0c09551f470",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "17234532-eee8-4410-ae56-e76538dc839b",
            "value": "b81d2293b43decd5a401487da952deb32cbb53f118882b97b457a14c67029247",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "528be816-9ed6-4704-8e72-1aeed9480cf2",
        "timestamp": "1606486060",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "13f34cbd-72ca-4e57-bc0c-16ce7b642a63",
            "value": "2020-11-11T06:44:55+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "c4f964b7-e843-46de-bfdd-cd32bdd760f0",
            "value": "https://www.virustotal.com/gui/file/b81d2293b43decd5a401487da952deb32cbb53f118882b97b457a14c67029247/detection/f-b81d2293b43decd5a401487da952deb32cbb53f118882b97b457a14c67029247-1605077095",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "97d457ff-af10-41db-ad63-3767dd4b81ed",
            "value": "51/65",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "936c65cd-2c49-4256-b729-d9b4c4276122",
        "timestamp": "1606486060",
        "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "description": "File object describing a file with meta-information",
        "distribution": "5",
        "meta-category": "file",
        "template_version": "22",
        "sharing_group_id": "0",
        "comment": "",
        "name": "file",
        "deleted": false,
        "ObjectReference": [
          {
            "uuid": "ec37a615-9a7c-4e72-8d2f-89272ff3975f",
            "timestamp": "0",
            "referenced_uuid": "baa1bfd9-4c36-4813-a30e-b8e84dd856a5",
            "object_uuid": "936c65cd-2c49-4256-b729-d9b4c4276122",
            "comment": "",
            "relationship_type": "analysed-with"
          }
        ],
        "Attribute": [
          {
            "uuid": "d1314ceb-c385-411d-9577-bf9f5af6411c",
            "value": "d1bd2fed0f6947dcb23e4c3da98a772e",
            "timestamp": "1606485659",
            "type": "md5",
            "to_ids": true,
            "comment": "",
            "object_relation": "md5",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "7df8a889-b11f-4b25-9106-dc8a080b22ae",
            "value": "edf4e9b226c9e8935fb38e7c3b864cf93e6d119c",
            "timestamp": "1606485659",
            "type": "sha1",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha1",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "c0157001-8cb1-49d0-9482-16f4f5fc06ad",
            "value": "605c2047be7c4a17823ad1fa5c1f94fd105721fce3621dc9148cd3baf352938e",
            "timestamp": "1606485659",
            "type": "sha256",
            "to_ids": true,
            "comment": "",
            "object_relation": "sha256",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      },
      {
        "uuid": "baa1bfd9-4c36-4813-a30e-b8e84dd856a5",
        "timestamp": "1606486061",
        "template_uuid": "d7dd0154-e04f-4c34-a2fb-79f3a3a52aa4",
        "description": "VirusTotal report",
        "distribution": "5",
        "meta-category": "misc",
        "template_version": "3",
        "sharing_group_id": "0",
        "comment": "",
        "name": "virustotal-report",
        "deleted": false,
        "Attribute": [
          {
            "uuid": "9f70b46e-9ae5-4246-8e34-2ce74abac443",
            "value": "2020-11-25T08:45:26+00:00",
            "timestamp": "1606485659",
            "type": "datetime",
            "to_ids": false,
            "comment": "",
            "object_relation": "last-submission",
            "disable_correlation": false,
            "category": "Other",
            "deleted": false
          },
          {
            "uuid": "d8684b81-2320-4dfa-bd28-708bb660cd23",
            "value": "https://www.virustotal.com/gui/file/605c2047be7c4a17823ad1fa5c1f94fd105721fce3621dc9148cd3baf352938e/detection/f-605c2047be7c4a17823ad1fa5c1f94fd105721fce3621dc9148cd3baf352938e-1606293926",
            "timestamp": "1606485659",
            "type": "link",
            "to_ids": false,
            "comment": "",
            "object_relation": "permalink",
            "disable_correlation": false,
            "category": "Payload delivery",
            "deleted": false
          },
          {
            "uuid": "41647af9-72bb-4424-8de0-5d5d788dd0dc",
            "value": "54/68",
            "timestamp": "1606485659",
            "type": "text",
            "to_ids": false,
            "comment": "",
            "object_relation": "detection-ratio",
            "disable_correlation": true,
            "category": "Payload delivery",
            "deleted": false
          }
        ]
      }
    ]
  }
}