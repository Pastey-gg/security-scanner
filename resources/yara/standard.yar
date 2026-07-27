// ============================================================
// 1. PHISHING
// ============================================================

rule Phishing_Credential_Harvester_Generic
{
    meta:
        description = "Form fields for passwords/financial/SSN data combined with a mechanism to exfiltrate the submission (mail-out or remote POST) - the core structure of a phishing kit"
        category = "phishing"
        severity = "high"
        action = "review"

    strings:
        $field_pw  = /name\s*=\s*["']?(pass(word)?|pwd)["']?/ nocase
        $field_cc  = /name\s*=\s*["']?(cc(num|number)?|card_?number|cvv2?|expir(y|ation))["']?/ nocase
        $field_ssn = /name\s*=\s*["']?(ssn|social_?security)["']?/ nocase

        $exfil_mail = "mail(" nocase
        $exfil_curl = "curl_exec(" nocase
        $exfil_post = /file_get_contents\(\s*["']https?:\/\// nocase
        $exfil_send = "sendmail" nocase

    condition:
        (1 of ($field_*)) and (1 of ($exfil_*))
}

rule Phishing_Brand_Clone_Login
{
    meta:
        description = "Well-known brand name plus urgency/verification language plus a password login form - typical structure of a cloned login page"
        category = "phishing"
        severity = "medium"
        action = "review"

    strings:
        $brand1 = "paypal" nocase
        $brand2 = "office 365" nocase
        $brand3 = "office365" nocase
        $brand4 = "apple id" nocase
        $brand5 = "bank of america" nocase
        $brand6 = "wells fargo" nocase
        $brand7 = "netflix" nocase
        $brand8 = "chase online" nocase

        $urgency1 = "verify your account" nocase
        $urgency2 = "confirm your identity" nocase
        $urgency3 = "unusual activity" nocase
        $urgency4 = "account has been limited" nocase
        $urgency5 = "suspended due to" nocase

        $form    = /<form[^>]{0,300}(action|method)\s*=/ nocase
        $pwfield = /type\s*=\s*["']password["']/ nocase

    condition:
        (1 of ($brand*)) and (1 of ($urgency*)) and $form and $pwfield
}


// ============================================================
// 2. FINANCIAL FRAUD / CARDING
// ============================================================

rule Fraud_Carding_Terminology_Cluster
{
    meta:
        description = "Cluster of carding/payment-fraud terminology commonly used when selling stolen card data or fraud tutorials"
        category = "financial_fraud"
        severity = "high"
        action = "review"

    strings:
        $t1  = "fullz" nocase
        $t2  = "cvv2" nocase
        $t3  = "cc dump" nocase
        $t4  = "dumps+pin" nocase
        $t5  = "dumps with pin" nocase
        $t6  = "bin list" nocase
        $t7  = "card cloning" nocase
        $t8  = "skimmer" nocase
        $t9  = "carding method" nocase
        $t10 = "non vbv" nocase
        $t11 = "auto shop cc" nocase

    condition:
        2 of them
}

rule Fraud_Bulk_CardNumber_Pattern
{
    meta:
        description = "Several payment-card-shaped digit sequences in one paste, alongside expiry or CVV language - indicative of a leaked card dump rather than a one-off example"
        category = "financial_fraud"
        severity = "high"
        action = "review"

    strings:
        $card = /\b[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,4}\b/
        $exp  = /\b(0[1-9]|1[0-2])[\/\-][0-9]{2,4}\b/
        $cvv  = "cvv" nocase

    condition:
        #card >= 5 and ($exp or $cvv)
}

rule Fraud_BIN_Checker_Script
{
    meta:
        description = "Code structured to bulk-check card BIN ranges against issuer lookup services - common carding automation tooling"
        category = "financial_fraud"
        severity = "medium"
        action = "review"

    strings:
        $s1 = "bin checker" nocase
        $s2 = "binlist" nocase
        $s3 = "issuer bank" nocase
        $s4 = "card scheme" nocase
        $s5 = "live bins" nocase

    condition:
        2 of them
}


// ============================================================
// 3. SCAMS
// ============================================================

rule Scam_Crypto_Giveaway
{
    meta:
        description = "Send-crypto-get-double-back giveaway scam pattern, frequently impersonating celebrities or exchanges"
        category = "crypto_scam"
        severity = "high"
        action = "review"

    strings:
        $send1 = "send btc" nocase
        $send2 = "send bitcoin" nocase
        $send3 = "send eth" nocase
        $send4 = "send usdt" nocase

        $double1 = "receive double" nocase
        $double2 = "get 2x back" nocase
        $double3 = "double your crypto" nocase
        $double4 = "2x return" nocase

        $giveaway = "giveaway" nocase
        $celeb1 = "elon musk" nocase
        $celeb2 = "vitalik buterin" nocase

        $verify = "verify your wallet address by sending" nocase

    condition:
        ((1 of ($send*)) and (1 of ($double*)))
        or ($giveaway and (1 of ($celeb*)))
        or $verify
}

rule Scam_Seed_Phrase_Phishing
{
    meta:
        description = "Prompts a visitor to enter their wallet seed phrase or private key - the core mechanism of a wallet-drainer scam page"
        category = "crypto_scam"
        severity = "critical"
        action = "review"

    strings:
        $s1 = "seed phrase" nocase
        $s2 = "recovery phrase" nocase
        $s3 = "12 word" nocase
        $s4 = "24 word" nocase
        $s5 = "private key" nocase

        $p1 = "enter your" nocase
        $p2 = "confirm your" nocase
        $p3 = "connect wallet" nocase
        $p4 = "validate your wallet" nocase

    condition:
        (1 of ($s*)) and (1 of ($p*))
}

rule Scam_AdvanceFee_419
{
    meta:
        description = "Language typical of advance-fee, inheritance, or romance scam letters (419 scams)"
        category = "advance_fee_scam"
        severity = "medium"
        action = "review"

    strings:
        $s1  = "dear beloved" nocase
        $s2  = "i am writing to you" nocase
        $s3  = "next of kin" nocase
        $s4  = "western union" nocase
        $s5  = "moneygram" nocase
        $s6  = "processing fee" nocase
        $s7  = "customs clearance" nocase
        $s8  = "stranded" nocase
        $s9  = "deployed" nocase
        $s10 = "diplomatic" nocase
        $s11 = "god fearing" nocase
        $s12 = "compensation fund" nocase

    condition:
        3 of them
}

rule Scam_Tech_Support
{
    meta:
        description = "Fake tech-support / malware-warning script language directing a victim to call a number or install remote-access software"
        category = "tech_support_scam"
        severity = "medium"
        action = "review"

    strings:
        $s1 = "your computer has been infected" nocase
        $s2 = "call microsoft support" nocase
        $s3 = "call this number immediately" nocase
        $s4 = "do not restart your computer" nocase
        $s5 = "anydesk" nocase
        $s6 = "teamviewer" nocase
        $s7 = "your license has expired" nocase

    condition:
        2 of them
}

rule Scam_Shortened_URL_With_Urgency
{
    meta:
        description = "Link-shortener domains combined with urgency/reward language - a common vector for distributing scam or phishing links via paste"
        category = "scam_links"
        severity = "low"
        action = "review"

    strings:
        $short1 = "bit.ly/" nocase
        $short2 = "tinyurl.com/" nocase
        $short3 = "is.gd/" nocase
        $short4 = "cutt.ly/" nocase

        $urgent1 = "claim your" nocase
        $urgent2 = "act now" nocase
        $urgent3 = "limited time" nocase
        $urgent4 = "click here to verify" nocase

    condition:
        (1 of ($short*)) and (1 of ($urgent*))
}


// ============================================================
// 4. MALWARE / WEBSHELLS BEING SHARED
// ============================================================
// Detection signatures only - no functional payloads.

rule Malware_Webshell_Generic
{
    meta:
        description = "Known webshell family names, or PHP superglobals passed directly into code-execution functions - indicates a shared web backdoor"
        category = "malware"
        severity = "critical"
        action = "review"

    strings:
        $name1 = "c99shell" nocase
        $name2 = "r57shell" nocase
        $name3 = "wso webshell" nocase
        $name4 = "b374k" nocase
        $name5 = "china chopper" nocase

        $func1 = /eval\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $func2 = /system\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $func3 = /passthru\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $func4 = /assert\s*\(\s*\$_(POST|GET|REQUEST)/ nocase

    condition:
        (1 of ($name*)) or (1 of ($func*))
}

rule Malware_Obfuscated_PHP_Chain
{
    meta:
        description = "Layered base64/gzinflate/eval obfuscation chain commonly used to hide backdoor payloads in PHP pastes"
        category = "malware"
        severity = "high"
        action = "review"

    strings:
        $s1 = "eval(base64_decode(" nocase
        $s2 = "eval(gzinflate(base64_decode(" nocase
        $s3 = "eval(gzuncompress(" nocase
        $s4 = "eval(str_rot13(" nocase
        $blob = /\$[a-zA-Z_]{1,3}\s*=\s*["'][A-Za-z0-9+\/=]{200,}["']/

    condition:
        (1 of ($s1,$s2,$s3,$s4)) or $blob
}

rule Malware_Ransomware_Note_Template
{
    meta:
        description = "Ransom-note boilerplate: encryption claim, payment deadline, and a crypto wallet address or .onion payment portal"
        category = "malware"
        severity = "high"
        action = "review"

    strings:
        $enc1 = "your files have been encrypted" nocase
        $enc2 = "all your files are encrypted" nocase
        $enc3 = "to decrypt your files" nocase

        $pay1      = "pay the ransom" nocase
        $deadline1 = "you have 72 hours" nocase
        $deadline2 = "you have 48 hours" nocase

        $wallet_legacy = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        $wallet_bech32 = /\bbc1[a-z0-9]{25,59}\b/ nocase
        $tor = ".onion" nocase

    condition:
        (1 of ($enc*)) and (1 of ($pay1,$deadline1,$deadline2,$wallet_legacy,$wallet_bech32,$tor))
}

rule Malware_Browser_Credential_Stealer
{
    meta:
        description = "Code referencing browser-stored credential databases (Chrome's Login Data, Firefox's key4.db, etc.) - typical of infostealer source shared as a paste"
        category = "malware"
        severity = "high"
        action = "review"

    strings:
        $s1 = "Login Data" nocase
        $s2 = "Local State" nocase
        $s3 = "key4.db" nocase
        $s4 = "cookies.sqlite" nocase
        $s5 = "CryptUnprotectData" nocase
        $s6 = "chrome_decrypt" nocase

    condition:
        3 of them
}


// ============================================================
// 5. LEAKED DATA
// ============================================================

rule Leak_Combolist_Format
{
    meta:
        description = "Many email:password formatted lines in one paste - typical of a leaked-credential combolist"
        category = "data_leak"
        severity = "high"
        action = "review"

    strings:
        $combo = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s:]{4,}/

    condition:
        #combo >= 10
}

rule Leak_Database_Dump_Markers
{
    meta:
        description = "SQL export headers combined with sensitive column names - indicates a leaked or stolen database dump rather than ordinary sample code"
        category = "data_leak"
        severity = "high"
        action = "review"

    strings:
        $hdr1 = "phpMyAdmin SQL Dump" nocase
        $hdr2 = "mysqldump" nocase
        $hdr3 = "pg_dump" nocase

        $col1 = "password_hash" nocase
        $col2 = "ssn" nocase
        $col3 = "credit_card" nocase
        $col4 = "date_of_birth" nocase

    condition:
        (1 of ($hdr*)) and (1 of ($col*))
}


// ============================================================
// 6. ILLEGAL GOODS / MARKETPLACES
// ============================================================

rule Illegal_Counterfeit_Documents
{
    meta:
        description = "Advertising language for counterfeit government-issued identification or travel documents"
        category = "illegal_goods"
        severity = "high"
        action = "review"

    strings:
        $s1 = "fake id" nocase
        $s2 = "fake passport" nocase
        $s3 = "scannable fake" nocase
        $s4 = "buy real and fake documents" nocase
        $s5 = "counterfeit driver" nocase

    condition:
        1 of them
}

rule Illegal_Weapons_Sale_Language
{
    meta:
        description = "Advertising language for unlicensed firearm or weapon sales"
        category = "illegal_goods"
        severity = "high"
        action = "review"

    strings:
        $s1 = "no ffl required" nocase
        $s2 = "untraceable firearm" nocase
        $s3 = "no background check required" nocase
        $s4 = "guns no license" nocase

    condition:
        1 of them
}

rule Illegal_DarkWeb_Marketplace_Generic
{
    meta:
        description = "A .onion address co-occurring with vendor/marketplace language typical of illicit-goods listings. Intentionally does not enumerate specific markets or vendors - supply your own vetted, regularly-updated onion-domain list as an external variable rather than hardcoding addresses here"
        category = "illegal_goods"
        severity = "medium"
        action = "review"

    strings:
        $onion   = /[a-z2-7]{16,56}\.onion/ nocase
        $vendor1 = "vendor" nocase
        $vendor2 = "escrow" nocase
        $vendor3 = "stealth shipping" nocase
        $vendor4 = "ships worldwide" nocase
        $drug1   = "shipped discreetly" nocase

    condition:
        $onion and ((1 of ($vendor*)) or $drug1)
}


// ============================================================
// 7. EVASION HEURISTICS
// ============================================================

rule Suspicious_Heavy_Obfuscation_Generic
{
    meta:
        description = "Unusually heavy hex/unicode escaping or character-code concatenation, often used to evade keyword-based filters (including this ruleset) - treat as a soft signal, not standalone evidence"
        category = "evasion"
        severity = "low"
        action = "review"

    strings:
        $hex     = /(\\x[0-9a-fA-F]{2}){12,}/
        $unicode = /(\\u[0-9a-fA-F]{4}){12,}/
        $charcat = /(chr\(\d{1,3}\)\s*\.\s*){10,}/ nocase

    condition:
        any of them
}
