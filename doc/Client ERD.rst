1. INTRODUCTION:
NOST client (nostclient) is a python client for the extended access to NexentaSwift over CCOW API.

2. DESCRIPTION:
One of the client possibilities is using multi-threading for file upload and download. Each file  can be divided into small pieces (chunks) and loaded separately. User can choose the size of the chunk or it will be assigned automatically. 

2.1 Product Perspective
Native cloudarchive integration.

Authentication - for getting access used keystone.

     Keystone implements identity API v2. When using keystone it's necessary to change auth_url from storage url to keystone access point (i.e.: when using tempauth storage access url is "https://localhost:8080/auth/v1.0" we need to change it to "https://localhost:5000/v2.0" (5000 is keystone default port))
    
Here is an request example:

POST /v2.0/tokens HTTP/1.1
Host: cloudstorage.nexenta.com
Content-Type: application/json
Accept: application/xml

{
    "auth":{
        "passwordCredentials":{
            "username": "test_user",
            "password": "mypass"
       },
   "tenantName": "customer-x"
    }
}

     ACL - access policies for container or manifest read/write permissions.

Here is an request example:

POST /v1.0/auth HTTP/1.1
X-Container-Acl-Write: admin:user
X-Container-Acl-Read: everyone 

     Multi-versioning - by default should be returned the newest object,  by option --version it will be possible to get any version. Because this is realized infinity storage period for previous versions and unlimited max versions count.

     Deduplication - if the same chunk will be uploaded, it will be changed only meta, without object duplication.


2.2 Product Features


2.2.1 Basic functionality
At the present moment:
general options:
            -A, --auth — URL for obtaining an auth token;
            -V, --auth-version — specify a version for authentication;
            -U, --user — user name for obtaining an auth token;
            -K, --key — user key for obtainig an auth token;
            -H, --proxy-hostname — host name for proxy connection;
            -P, --proxy-port — port for proxy connection ;
	    -c, --configure-file — configure file for loading configures;
            -v, --verbose — allows to write debug message to console;

2.2.2 Configure
configure [options]
saves configures to config file.
Settings are saved in a convenient representation, it facilitates the initial configuration of  repository access and makes futher use more comfortable.
Here is an example of storage configures:
[CONFIG]
auth_url = http://127.0.0.1:8080/auth/v1.0/
auth_version = 1.0
user = admin:admin
key = admin

2.2.3 Upload
upload [options] container file
        Uploads to the given container the files specified by the remaining argument 
--chunk-size - chunk size
-w --workers - number of workers threads
-q --quit - number of workers threads
--concurrent-thread — specifies the number of threads

2.2.4 Download
download [options] container manifest [chunk]
Downloads from the given container the files specified by the remaining argument
--version-id - allows to download object given version_id
--only-manifest - allows to get only information from manifest, without
                         downloading.
--only-chunk - allows to get only given chunk
-q --quit - hide progress bar
--concurrent-thread — specifies the number of threads

2.2.5 List
list [container] [manifest]
Shows list for the account, container or list of chunks from the manifest
-f --full - show full listing of objects
-l --limit - limit for items to show
-p --prefix - shows only list items beginning with that prefix
-d --delimiter - rolls up items with the given delimiter
-m --marker - rolls up items with the given marker
--end-marker - rolls up items which less then the given marker
--versions - shows only list items having version_id (for container
                     listings only)
--vmarker - rolls up items with the given vmarker for version id
--end-vmarker - rolls up items which version id less then the given
                        vmarker
--version-id - allows to list manifest chunks of given version id

2.2.6 Stat
stat [container] [manifest]
Displays metadata for the account, container or manifest.
--version-id - allows to get information about object given version_id

2.2.7 Delete
delete container [manifest]
Deletes container from the account or manifest from given container.
--version-id - allows to delete given manifest version id
--all - allows to delete everything from given container

2.2.8 Versioning
versioning container [enabled|suspended]
Shows versioning support for given container. 
Allows to switch it using enabled or suspended as a remaining arguments.

2.2.9 ACL
acl container [manifest]
Displays ACL information for the container or manifest depending on the
    args given (if any).
--version-id - allows to get or set ACL of given manifest version id
--acp - to change container or manifest ACL
	(only if changer has WRITE_ACP permission)
example:
--acp 'account:user1 READ_ACP, WRITE; account:user2 FULL_CONTROL'

