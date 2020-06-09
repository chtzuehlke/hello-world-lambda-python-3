Fun with keys :)

Setup

    aws kms create-key --key-usage SIGN_VERIFY --customer-master-key-spec ECC_NIST_P256 --no-bypass-policy-lockout-safety-check > key-meta.json

    export KMS_KEY_ARN=$(cat key-meta.json | jq -r ".KeyMetadata.Arn")
    sls deploy

Test

    sls invoke -f hello > result.json

    cat result.json | jq -r ".publickey" | base64 -d > pubkey.der
    openssl ec -pubin -in pubkey.der -inform DER -outform PEM -out pubkey.pem

    cat result.json | jq -r ".signature" | base64 -d > hello.sig

    echo "hello world" > hello.txt 
    truncate -s -1 hello.txt 

    openssl dgst -sha256 -verify pubkey.pem -signature hello.sig hello.txt
