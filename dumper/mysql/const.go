package mysql

const (
	comQuery       = 0x03
	comStmtPrepare = 0x16
	comStmtExecute = 0x17

	comStmtPrepareOK = 0x00
)

type dataType byte

const (
	typeDecimal    dataType = 0x00
	typeTiny                = 0x01
	typeShort               = 0x02
	typeLong                = 0x03
	typeFloat               = 0x04
	typeDouble              = 0x05
	typeNull                = 0x06
	typeTimestamp           = 0x07
	typeLonglong            = 0x08
	typeInt24               = 0x09
	typeDate                = 0x0a
	typeTime                = 0x0b
	typeDatetime            = 0x0c
	typeYear                = 0x0d
	typeNewdate             = 0x0e
	typeVarchar             = 0x0f
	typeBit                 = 0x10
	typeNewdecimal          = 0xf6
	typeEnum                = 0xf7
	typeSet                 = 0xf8
	typeTinyBlob            = 0xf9
	typeMediumblob          = 0xfa
	typeLongblob            = 0xfb
	typeBlob                = 0xfc
	typeVarString           = 0xfd
	typeString              = 0xfe
	typeGeometry            = 0xff
)

type clientCapability uint32

const (
	clientLongPassword clientCapability = 1 << iota
	clientFoundRows
	clientLongFlag
	clientConnectWithDB
	clientNoSchema
	clientCompress
	clientODBC
	clientLocalFiles
	clientIgnoreSpace
	clientProtocol41
	clientInteractive
	clientSSL
	clientIgnoreSIGPIPE
	clientTransactions
	clientReserved
	clientSecureConnection
	clientMultiStatements
	clientMultiResults
	clientPSMultiResults
	clientPluginAuth
	clientConnectAttrs
	clientPluginAuthLenEncClientData
	clientCanHandleExpiredPasswords
	clientSessionTrack
	clientDeprecateEOF
)

type charSet uint32

const (
	charSetUnknown  charSet = 0
	charSetBig5             = 1
	charSetDec8             = 3
	charSetCp850            = 4
	charSetHp8              = 6
	charSetKoi8r            = 7
	charSetLatin1           = 8
	charSetLatin2           = 9
	charSetSwe7             = 10
	charSetASCII            = 11
	charSetUjis             = 12
	charSetSjis             = 13
	charSetHebrew           = 16
	charSetTis620           = 18
	charSetEuckr            = 19
	charSetKoi8u            = 22
	charSetGb2312           = 24
	charSetGreek            = 25
	charSetCp1250           = 26
	charSetGbk              = 28
	charSetLatin5           = 30
	charSetArmscii8         = 32
	charSetUtf8             = 33
	charSetUcs2             = 35
	charSetCp866            = 36
	charSetKeybcs2          = 37
	charSetMacce            = 38
	charSetMacroman         = 39
	charSetCp852            = 40
	charSetLatin7           = 41
	charSetCp1251           = 51
	charSetUtf16            = 54
	charSetUtf16le          = 56
	charSetCp1256           = 57
	charSetCp1257           = 59
	charSetUtf32            = 60
	charSetBinary           = 63
	charSetGeostd8          = 92
	charSetCp932            = 95
	charSetEucjpms          = 97
	charSetGb18030          = 248
	charSetUtf8mb4          = 255
)

func (c charSet) String() string {
	switch c {
	case charSetBig5:
		return "big5"
	case charSetDec8:
		return "dec8"
	case charSetCp850:
		return "cp850"
	case charSetHp8:
		return "hp8"
	case charSetKoi8r:
		return "koi8r"
	case charSetLatin1:
		return "latin1"
	case charSetLatin2:
		return "latin2"
	case charSetSwe7:
		return "swe7"
	case charSetASCII:
		return "ascii"
	case charSetUjis:
		return "ujis"
	case charSetSjis:
		return "sjis"
	case charSetHebrew:
		return "hebrew"
	case charSetTis620:
		return "tis620"
	case charSetEuckr:
		return "euckr"
	case charSetKoi8u:
		return "koi8u"
	case charSetGb2312:
		return "gb2312"
	case charSetGreek:
		return "greek"
	case charSetCp1250:
		return "cp1250"
	case charSetGbk:
		return "gbk"
	case charSetLatin5:
		return "latin5"
	case charSetArmscii8:
		return "armscii8"
	case charSetUtf8:
		return "utf8"
	case charSetUcs2:
		return "ucs2"
	case charSetCp866:
		return "cp866"
	case charSetKeybcs2:
		return "keybcs2"
	case charSetMacce:
		return "macce"
	case charSetMacroman:
		return "macroman"
	case charSetCp852:
		return "cp852"
	case charSetLatin7:
		return "latin7"
	case charSetCp1251:
		return "cp1251"
	case charSetUtf16:
		return "utf16"
	case charSetUtf16le:
		return "utf16le"
	case charSetCp1256:
		return "cp1256"
	case charSetCp1257:
		return "cp1257"
	case charSetUtf32:
		return "utf32"
	case charSetBinary:
		return "binary"
	case charSetGeostd8:
		return "geostd8"
	case charSetCp932:
		return "cp932"
	case charSetEucjpms:
		return "eucjpms"
	case charSetGb18030:
		return "gb18030"
	case charSetUtf8mb4:
		return "utf8mb4"
	default:
		return ""
	}
}
