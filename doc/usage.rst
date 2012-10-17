configure [options]
    Save configs to config file, default file path is /home/arma/.nostclient.
        -c --config-file - path to config file for saving configures.

stat [container] [manifest]
    Displays information for the account, container or manifest
    depending on the args given (if any).
    --version-id - allows to get information about object given version_id

list [container] [manifest] [options]
    Shows list for the account, container or list of chunks from the manifest
    depending on the args given (if any).
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

download <container> <manifest> [<chunk>] [options]
    Downloads from the given container the objects specified by the
    remaining args.
    --version-id - allows to download object given version_id
    --only-manifest - allows to get only information from manifest, without
                         downloading.
    --only-chunk - allows to get only given chunk
    -q --quit - hide progress bar

upload [container] [file] [options]
    Uploads to the given container the files specified by the remaining args.
    --chunk-size - chunk size
    -w --workers - number of workers threads
    -q --quit - number of workers threads

delete <container> [manifest]
    Deletes container or manifest depending on the args given (if any).
    --version-id - allows to delete given manifest version id

versioning <container> [enabled|suspended]
    Shows versioning support for given container. Allows to switch it using
    enabled or suspended as a remaining args.

acl <container> [manifest]
    Displays ACL information for the container or manifest depending on the
    args given (if any).
    --version-id - allows to get or set ACL of given manifest version id
    --acp - to change container or manifest ACL
            (only if changer has WRITE_ACP permission)
            example:
            --acp 'account:user1 READ_ACP, WRITE; account:user2 FULL_CONTROL'
