# BlackboxProtobuf x YouTube
Network communications between YouTube{,Music,Creator} mobile apps and Google's backend are made using Protobuf, which increases the difficulty of analyzing them.  
<br/>
However, apparently, appending `?alt=json` to the query string changes the API response encoding from Protobuf to JSON.  
<br/>
This Burp extension uses [NCC Group's Blackbox Protobuf](https://github.com/nccgroup/blackboxprotobuf) library to decode Protobuf payloads, issues a `alt=json` request, and then map the JSON <-> Protobuf responses to derive type definition.  
<br/>
<img width="1163" alt="image" src="https://github.com/user-attachments/assets/29105343-771f-4972-b9cd-49516f131caf">

## Installation
1. `git clone https://github.com/lorenzodifuccia/YoutubeProtobuf && cd YoutubeProtobuf`
2. `git submodule update --init --recursive`
3. Configure Jython and add `extender.py` in Burp Extensions.

## Usage
Right-click on a YouTube request > `Extensions` > `BlackboxProtobuf x YouTube` > `Send 'alt=json' request`  
If successful, a new Issue will be generated with the type definition to import in BlackboxProtobuf:  
<br/>
<img width="949" alt="image" src="https://github.com/user-attachments/assets/66525c53-3a1b-4758-af9f-1c698d873f5f">
<br/><br/>
<img width="950" alt="image" src="https://github.com/user-attachments/assets/043572e2-a493-4590-8e44-afbcd10bc554">
