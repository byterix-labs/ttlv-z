//! TTLV enumeration definitions for tag types and value types.
//!
//! This module contains the standard KMIP (Key Management Interoperability Protocol)
//! enumeration definitions used in TTLV encoding. It includes all value types that
//! can be encoded in TTLV format and the complete set of KMIP tag definitions
//! from versions 1.0 through 3.0.

/// TTLV value type enumeration as defined by the KMIP specification.
/// Each value corresponds to a specific data type that can be encoded in TTLV format.
pub const ValueType = enum(u8) {
    /// Nested structure containing other TTLV elements
    structure = 0x1,
    /// 32-bit signed integer
    integer = 0x2,
    /// 64-bit signed integer
    longInteger = 0x3,
    /// 128-bit signed integer
    bigInteger = 0x4,
    /// 32-bit enumeration value
    enumeration = 0x5,
    /// Boolean value (encoded as 8 bytes)
    boolean = 0x06,
    /// UTF-8 text string
    textString = 0x7,
    /// Binary byte string
    byteString = 0x8,
    /// Date/time timestamp
    dateTime = 0x9,
    /// Time interval value
    interval = 0xA,
    /// Extended date/time timestamp
    dateTimeExtended = 0xB,
    /// Object identifier string
    identifier = 0xC,
    /// Reference to another object
    reference = 0xD,
    /// Named reference to another object
    nameReference = 0xE,
    /// Empty/null value
    none,

    /// Returns metadata information for this value type.
    ///
    /// Returns:
    ///   ValueTypeMeta containing size and padding information for this type
    pub fn meta(self: @This()) ValueTypeMeta {
        return ValueTypeMeta[self];
    }
};

fn valueTypeMeta(comptime size: type, comptime padding: type) type {
    return struct {
        size: size,
        padding: padding,
    };
}

/// Metadata information for TTLV value types.
/// Contains size and padding requirements for each value type during encoding/decoding.
pub const ValueTypeMeta = union(ValueType) {
    structure: @TypeOf(.none),
    integer: valueTypeMeta(i32, u32),
    longInteger: valueTypeMeta(i64, void),
    bigInteger: valueTypeMeta(i128, void),
    enumeration: valueTypeMeta(u32, u32),
    boolean: valueTypeMeta(u64, void),
    textString: @TypeOf(.none),
    byteString: @TypeOf(.none),
    dateTime: valueTypeMeta(u64, void),
    interval: valueTypeMeta(u32, u32),
    dateTimeExtended: @TypeOf(.none),
    identifier: @TypeOf(.none),
    reference: @TypeOf(.none),
    nameReference: @TypeOf(.none),
    none: @TypeOf(.none),
};

/// KMIP tag type enumeration containing all standard KMIP tags.
///
/// This enum includes all official KMIP tags from versions 1.0 through 3.0 of the
/// Key Management Interoperability Protocol specification. Each tag identifies
/// a specific data element in KMIP messages.
///
/// Tags are organized by KMIP version and functionality area. Reserved tags
/// are commented out to maintain the correct enum values while preventing usage.
pub const TagType = enum(u24) {
    // KMIP 1.0
    activationDate = 0x420001,
    applicationData = 0x420002,
    applicationNamespace = 0x420003,
    applicationSpecificInformation = 0x420004,
    archiveDate = 0x420005,
    asynchronousCorrelationValue = 0x420006,
    asynchronousIndicator = 0x420007,
    attribute = 0x420008,
    // Reserved = 0x420009,
    attributeName = 0x42000A,
    attributeValue = 0x42000B,
    authentication = 0x42000C,
    // Reserved = 0x42000D,
    batchErrorContinuationOption = 0x42000E,
    batchItem = 0x42000F,
    // Reserved = 0x420010,
    blockCipherMode = 0x420011,
    cancellationResult = 0x420012,
    certificate = 0x420013,
    // Reserved = 0x420014,
    // Reserved = 0x420015,
    // Reserved = 0x420016,
    // Reserved = 0x420017,
    certificateRequest = 0x420018,
    certificateRequestType = 0x420019,
    // Reserved = 0x42001A,
    // Reserved = 0x42001B,
    // Reserved = 0x42001C,
    certificateType = 0x42001D,
    certificateValue = 0x42001E,
    // Reserved = 0x42001F,
    compromiseDate = 0x420020,
    compromiseOccurrenceDate = 0x420021,
    contactInformation = 0x420022,
    credential = 0x420023,
    credentialType = 0x420024,
    credentialValue = 0x420025,
    criticalityIndicator = 0x420026,
    crtCoefficient = 0x420027,
    cryptographicAlgorithm = 0x420028,
    cryptographicDomainParameters = 0x420029,
    cryptographicLength = 0x42002A,
    cryptographicParameters = 0x42002B,
    cryptographicUsageMask = 0x42002C,
    // Reserved = 0x42002D,
    d = 0x42002E,
    deactivationDate = 0x42002F,
    derivationData = 0x420030,
    derivationMethod = 0x420031,
    derivationParameters = 0x420032,
    destroyDate = 0x420033,
    digest = 0x420034,
    digestValue = 0x420035,
    encryptionKeyInformation = 0x420036,
    g = 0x420037,
    hashingAlgorithm = 0x420038,
    initialDate = 0x420039,
    initializationVector = 0x42003A,
    // Reserved = 0x42003B,
    iterationCount = 0x42003C,
    iVCounterNonce = 0x42003D,
    j = 0x42003E,
    key = 0x42003F,
    keyBlock = 0x420040,
    keyCompressionType = 0x420041,
    keyFormatType = 0x420042,
    keyMaterial = 0x420043,
    keyPartIdentifier = 0x420044,
    keyValue = 0x420045,
    keyWrappingData = 0x420046,
    keyWrappingSpecification = 0x420047,
    lastChangeDate = 0x420048,
    leaseTime = 0x420049,
    // Reserved = 0x42004A,
    // Reserved = 0x42004B,
    // Reserved = 0x42004C,
    macSignature = 0x42004D,
    macSignatureKeyInformation = 0x42004E,
    maximumItems = 0x42004F,
    maximumResponseSize = 0x420050,
    messageExtension = 0x420051,
    modulus = 0x420052,
    name = 0x420053,
    // Reserved = 0x420054,
    // Reserved = 0x420055,
    // Reserved = 0x420056,
    objectType = 0x420057,
    offset = 0x420058,
    opaqueDataType = 0x420059,
    opaqueDataValue = 0x42005A,
    opaqueObject = 0x42005B,
    operation = 0x42005C,
    // Reserved = 0x42005D,
    p = 0x42005E,
    paddingMethod = 0x42005F,
    primeExponentP = 0x420060,
    primeExponentQ = 0x420061,
    primeFieldSize = 0x420062,
    privateExponent = 0x420063,
    privateKey = 0x420064,
    // (Reserved) = 0x420065,
    privateKeyUniqueIdentifier = 0x420066,
    processStartDate = 0x420067,
    protectStopDate = 0x420068,
    protocolVersion = 0x420069,
    protocolVersionMajor = 0x42006A,
    protocolVersionMinor = 0x42006B,
    publicExponent = 0x42006C,
    publicKey = 0x42006D,
    // Reserved = 0x42006E,
    publicKeyUniqueIdentifier = 0x42006F,
    putFunction = 0x420070,
    q = 0x420071,
    qString = 0x420072,
    qlength = 0x420073,
    queryFunction = 0x420074,
    recommendedCurve = 0x420075,
    replacedUniqueIdentifier = 0x420076,
    requestHeader = 0x420077,
    requestMessage = 0x420078,
    requestPayload = 0x420079,
    responseHeader = 0x42007A,
    responseMessage = 0x42007B,
    responsePayload = 0x42007C,
    resultMessage = 0x42007D,
    resultReason = 0x42007E,
    resultStatus = 0x42007F,
    revocationMessage = 0x420080,
    revocationReason = 0x420081,
    revocationReasonCode = 0x420082,
    keyRoleType = 0x420083,
    salt = 0x420084,
    secretData = 0x420085,
    secretDataType = 0x420086,
    // Reserved = 0x420087,
    serverInformation = 0x420088,
    splitKey = 0x420089,
    splitKeyMethod = 0x42008A,
    splitKeyParts = 0x42008B,
    splitKeyThreshold = 0x42008C,
    state = 0x42008D,
    storageStatusMask = 0x42008E,
    symmetricKey = 0x42008F,
    // Reserved = 0x420090,
    // Reserved = 0x420091,
    timeStamp = 0x420092,
    // Reserved = 0x420093,
    uniqueIdentifier = 0x420094,
    usageLimits = 0x420095,
    usageLimitsCount = 0x420096,
    usageLimitsTotal = 0x420097,
    usageLimitsUnit = 0x420098,
    username = 0x420099,
    validityDate = 0x42009A,
    validityIndicator = 0x42009B,
    vendorExtension = 0x42009C,
    vendorIdentification = 0x42009D,
    wrappingMethod = 0x42009E,
    x = 0x42009F,
    y = 0x4200A0,
    password = 0x4200A1,
    // KMIP 1.1,
    deviceIdentifier = 0x4200A2,
    encodingOption = 0x4200A3,
    extensionInformation = 0x4200A4,
    extensionName = 0x4200A5,
    extensionTag = 0x4200A6,
    extensionType = 0x4200A7,
    fresh = 0x4200A8,
    machineIdentifier = 0x4200A9,
    mediaIdentifier = 0x4200AA,
    networkIdentifier = 0x4200AB,
    // Reserved = 0x4200AC,
    certificateLength = 0x4200AD,
    digitalSignatureAlgorithm = 0x4200AE,
    certificateSerialNumber = 0x4200AF,
    deviceSerialNumber = 0x4200B0,
    issuerAlternativeName = 0x4200B1,
    issuerDistinguishedName = 0x4200B2,
    subjectAlternativeName = 0x4200B3,
    subjectDistinguishedName = 0x4200B4,
    x509CertificateIdentifier = 0x4200B5,
    x509CertificateIssuer = 0x4200B6,
    x509CertificateSubject = 0x4200B7,
    // KMIP 1.2,
    keyValueLocation = 0x4200B8,
    keyValueLocationValue = 0x4200B9,
    keyValueLocationType = 0x4200BA,
    keyValuePresent = 0x4200BB,
    originalCreationDate = 0x4200BC,
    pGPKey = 0x4200BD,
    pGPKeyVersion = 0x4200BE,
    alternativeName = 0x4200BF,
    alternativeNameValue = 0x4200C0,
    alternativeNameType = 0x4200C1,
    data = 0x4200C2,
    signatureData = 0x4200C3,
    dataLength = 0x4200C4,
    randomIV = 0x4200C5,
    macData = 0x4200C6,
    attestationType = 0x4200C7,
    nonce = 0x4200C8,
    nonceID = 0x4200C9,
    nonceValue = 0x4200CA,
    attestationMeasurement = 0x4200CB,
    attestationAssertion = 0x4200CC,
    ivLength = 0x4200CD,
    tagLength = 0x4200CE,
    fixedFieldLength = 0x4200CF,
    counterLength = 0x4200D0,
    initialCounterValue = 0x4200D1,
    invocationFieldLength = 0x4200D2,
    attestationCapableIndicator = 0x4200D3,
    // KMIP 1.3,
    offsetItems = 0x4200D4,
    locatedItems = 0x4200D5,
    correlationValue = 0x4200D6,
    initIndicator = 0x4200D7,
    finalIndicator = 0x4200D8,
    rngParameters = 0x4200D9,
    rngAlgorithm = 0x4200DA,
    drbgAlgorithm = 0x4200DB,
    fips186Variation = 0x4200DC,
    predictionResistance = 0x4200DD,
    randomNumberGenerator = 0x4200DE,
    validationInformation = 0x4200DF,
    validationAuthorityType = 0x4200E0,
    validationAuthorityCountry = 0x4200E1,
    validationAuthorityURI = 0x4200E2,
    validationVersionMajor = 0x4200E3,
    validationVersionMinor = 0x4200E4,
    validationType = 0x4200E5,
    validationLevel = 0x4200E6,
    validationCertificateIdentifier = 0x4200E7,
    validationCertificateURI = 0x4200E8,
    validationVendorURI = 0x4200E9,
    validationProfile = 0x4200EA,
    profileInformation = 0x4200EB,
    profileName = 0x4200EC,
    serverURI = 0x4200ED,
    serverPort = 0x4200EE,
    streamingCapability = 0x4200EF,
    asynchronousCapability = 0x4200F0,
    attestationCapability = 0x4200F1,
    unwrapMode = 0x4200F2,
    destroyAction = 0x4200F3,
    shreddingAlgorithm = 0x4200F4,
    rNGMode = 0x4200F5,
    clientRegistrationMethod = 0x4200F6,
    capabilityInformation = 0x4200F7,
    // KMIP 1.4,
    keyWrapType = 0x4200F8,
    batchUndoCapability = 0x4200F9,
    batchContinueCapability = 0x4200FA,
    pKCS12FriendlyName = 0x4200FB,
    description = 0x4200FC,
    comment = 0x4200FD,
    authenticatedEncryptionAdditionalData = 0x4200FE,
    authenticatedEncryptionTag = 0x4200FF,
    saltLength = 0x420100,
    maskGenerator = 0x420101,
    maskGeneratorHashingAlgorithm = 0x420102,
    pSource = 0x420103,
    trailerField = 0x420104,
    clientCorrelationValue = 0x420105,
    serverCorrelationValue = 0x420106,
    digestedData = 0x420107,
    certificateSubjectCN = 0x420108,
    certificateSubjectO = 0x420109,
    certificateSubjectOU = 0x42010A,
    certificateSubjectEmail = 0x42010B,
    certificateSubjectC = 0x42010C,
    certificateSubjectST = 0x42010D,
    certificateSubjectL = 0x42010E,
    certificateSubjectUID = 0x42010F,
    certificateSubjectSerialNumber = 0x420110,
    certificateSubjectTitle = 0x420111,
    certificateSubjectDC = 0x420112,
    certificateSubjectDNQualifier = 0x420113,
    certificateIssuerCN = 0x420114,
    certificateIssuerO = 0x420115,
    certificateIssuerOU = 0x420116,
    certificateIssuerEmail = 0x420117,
    certificateIssuerC = 0x420118,
    certificateIssuerST = 0x420119,
    certificateIssuerL = 0x42011A,
    certificateIssuerUID = 0x42011B,
    certificateIssuerSerialNumber = 0x42011C,
    certificateIssuerTitle = 0x42011D,
    certificateIssuerDC = 0x42011E,
    certificateIssuerDNQualifier = 0x42011F,
    sensitive = 0x420120,
    alwaysSensitive = 0x420121,
    extractable = 0x420122,
    neverExtractable = 0x420123,
    replaceExisting = 0x420124,
    // KMIP 2.0,
    attributes = 0x420125,
    commonAttributes = 0x420126,
    privateKeyAttributes = 0x420127,
    publicKeyAttributes = 0x420128,
    extensionEnumeration = 0x420129,
    extensionAttribute = 0x42012A,
    extensionParentStructureTag = 0x42012B,
    extensionDescription = 0x42012C,
    serverName = 0x42012D,
    serverSerialNumber = 0x42012E,
    serverVersion = 0x42012F,
    serverLoad = 0x420130,
    productName = 0x420131,
    buildLevel = 0x420132,
    buildDate = 0x420133,
    clusterInfo = 0x420134,
    alternateFailoverEndpoints = 0x420135,
    shortUniqueIdentifier = 0x420136,
    reserved = 0x420137,
    tag = 0x420138,
    certificateRequestUniqueIdentifier = 0x420139,
    nISTKeyType = 0x42013A,
    attributeReference = 0x42013B,
    currentAttribute = 0x42013C,
    newAttribute = 0x42013D,
    // Reserved = 0x42013E,
    // Reserved = 0x42013F,
    certificateRequestValue = 0x420140,
    logMessage = 0x420141,
    profileVersion = 0x420142,
    profileVersionMajor = 0x420143,
    profileVersionMinor = 0x420144,
    protectionLevel = 0x420145,
    protectionPeriod = 0x420146,
    quantumSafe = 0x420147,
    quantumSafeCapability = 0x420148,
    ticket = 0x420149,
    ticketType = 0x42014A,
    ticketValue = 0x42014B,
    requestCount = 0x42014C,
    rights = 0x42014D,
    objects = 0x42014E,
    operations = 0x42014F,
    right = 0x420150,
    endpointRole = 0x420151,
    defaultsInformation = 0x420152,
    objectDefaults = 0x420153,
    ephemeral = 0x420154,
    serverHashedPassword = 0x420155,
    oneTimePassword = 0x420156,
    hashedPassword = 0x420157,
    adjustmentType = 0x420158,
    pKCS11Interface = 0x420159,
    pKCS11Function = 0x42015A,
    pKCS11InputParameters = 0x42015B,
    pKCS11OutputParameters = 0x42015C,
    pKCS11ReturnCode = 0x42015D,
    protectionStorageMask = 0x42015E,
    protectionStorageMasks = 0x42015F,
    interopFunction = 0x420160,
    interopIdentifier = 0x420161,
    adjustmentValue = 0x420162,
    commonProtectionStorageMasks = 0x420163,
    privateProtectionStorageMasks = 0x420164,
    publicProtectionStorageMasks = 0x420165,
    // KMIP 3.0,
    objectGroups = 0x420166,
    objectTypes = 0x420167,
    constraints = 0x420168,
    constraint = 0x420169,
    rotateInterval = 0x42016A,
    rotateAutomatic = 0x42016B,
    rotateOffset = 0x42016C,
    rotateDate = 0x42016D,
    rotateGeneration = 0x42016E,
    rotateName = 0x42016F,
    // Reserved =  0x420170,
    // Reserved =  0x420171,
    rotateLatest = 0x420172,
    asynchronousRequest = 0x420173,
    submissionDate = 0x420174,
    processingStage = 0x420175,
    asynchronousCorrelationValues = 0x420176,
    certificateLink = 0x420190,
    childLink = 0x420191,
    derivationObjectLink = 0x420192,
    derivedObjectLink = 0x420193,
    nextLink = 0x420194,
    parentLink = 0x420195,
    pKCS12CertificateLink = 0x420196,
    pKCS12PasswordLink = 0x420197,
    previousLink = 0x420198,
    privateKeyLink = 0x420199,
    publicKeyLink = 0x42019A,
    replacedObjectLink = 0x42019B,
    replacementObjectLink = 0x42019C,
    wrappingKeyLink = 0x42019D,
    objectClass = 0x42019E,
    objectClassMask = 0x42019F,
    credentialLink = 0x4201A0,
    passwordCredential = 0x4201A1,
    passwordSalt = 0x4201A2,
    passwordSaltAlgorithm = 0x4201A3,
    saltedPassword = 0x4201A4,
    passwordLink = 0x4201A5,
    deviceCredential = 0x4201A6,
    oTPCredential = 0x4201A7,
    oTPAlgorithm = 0x4201A8,
    oTPDigest = 0x4201A9,
    oTPSerial = 0x4201AA,
    oTPSeed = 0x4201AB,
    oTPInterval = 0x4201AC,
    oTPDigits = 0x4201AD,
    oTPCounter = 0x4201AE,
    hashedPasswordCredential = 0x4201AF,
    hashedUsernamePassword = 0x4201B0,
    hashedPasswordUsername = 0x4201B1,
    credentialInformation = 0x4201B2,
    groupLink = 0x4201B3,
    splitKeyBaseLink = 0x4201B4,
    joinedSplitKeyPartsLink = 0x4201B5,
    splitKeyPolynomial = 0x4201B6,
    deactivationMessage = 0x4201B7,
    deactivationReason = 0x4201B8,
    deactivationReasonCode = 0x4201B9,
    certificateSubjectDN = 0x4201BA,
    certificateIssuerDN = 0x4201BB,
    certificateRequestLink = 0x4201BC,
    certifyCounter = 0x4201BD,
    decryptCounter = 0x4201BE,
    encryptCounter = 0x4201BF,
    signCounter = 0x4201C0,
    signatureVerifyCounter = 0x4201C1,
    nISTSecurityCategory = 0x4201C2,
    _,
};
