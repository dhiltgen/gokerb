package kerb

import (
	"bytes"
	"encoding/hex"
	//"fmt"
	"testing"
)

func mustHexDecode(str string) []byte {
	d, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return d
}

var desStringTests = []struct {
	salt, pass, key string
}{
	{"ATHENA.MIT.EDUraeburn", "password", "cbc22fae235298e3"},
	{"WHITEHOUSE.GOVdanny", "potatoe", "df3d32a74fd92a01"},
	{"EXAMPLE.COMpianist", "\U0001D11E", "4ffb26bab0cd9413"},
	{"ATHENA.MIT.EDUJuri\u0161i\u0107", "\u00df", "62c81a5232b5e69d"},
	{"AAAAAAAA", "11119999", "984054d0f1a73e31"},
	{"FFFFAAAA", "NNNN6666", "c4bf6b25adf7a4f8"},
}

func TestDesStringKey(t *testing.T) {
	//fmt.Printf("XXX d\n")
	for i, d := range desStringTests {
		key := desStringKey(d.pass, d.salt)
		if !bytes.Equal(key, mustHexDecode(d.key)) {
			t.Errorf("Test %d failed, got %x expected %s\n", i, key, d.key)
		}
	}
}

var gssDesTests = []struct {
	data, key, out string
}{
	{"7654321 Now is the time for ", "0123456789abcdef", "f1d30f6849312ca4"},
}

func TestGssDes(t *testing.T) {
	//fmt.Printf("XXX c\n")
	for i, d := range gssDesTests {
		k := mustLoadKey(cryptDesCbcMd5, mustHexDecode(d.key))
		chk, err := k.Sign(signGssDes, 0, []byte(d.data))
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
		}
		if !bytes.Equal(chk, mustHexDecode(d.out)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, chk, d.out)
		}
	}
}

var cryptTests = []struct {
	algo int
	key  string
	data string
}{
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789abcdef"},
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789"},
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789abcdef0123"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789abcdef"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789abcdef0123"},
	//{cryptAes256CtsHmac, "cbc22fae235298e3", "12"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{cryptAes128CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef01"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef0123456789abcd"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef01"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef0123456789abcd"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef01"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcdef"},
	{cryptAes256CtsHmac, "cbc22fae235298e3cbc22fae235298e3", "0123456789abcd"},
}

func TestCrypt(t *testing.T) {
	//fmt.Printf("XXX b\n")
	for i, d := range cryptTests {
		key := mustLoadKey(d.algo, mustHexDecode(d.key))
		enc := key.Encrypt(nil, paEncryptedTimestampKey, mustHexDecode(d.data))
		dec, err := key.Decrypt(nil, d.algo, paEncryptedTimestampKey, enc)
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
			continue
		}
		if !bytes.HasPrefix(dec, mustHexDecode(d.data)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, dec, d.data)
		}
	}
}

func TestCryptWithPasswordString(t *testing.T) {
	//fmt.Printf("XXX a\n")
	for i, d := range cryptTests {

		key, err := loadStringKey(d.algo, d.key, "mysalt")
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
			continue
		}
		enc := key.Encrypt(nil, paEncryptedTimestampKey, mustHexDecode(d.data))
		dec, err := key.Decrypt(nil, d.algo, paEncryptedTimestampKey, enc)
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
			continue
		}
		if !bytes.HasPrefix(dec, mustHexDecode(d.data)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, dec, d.data)
		}
	}
}

// Examples drawn from rfc3961 A.1
var foldTests = []struct {
	bits   uint
	input  string
	output string
}{
	{64, "012345", "be072631276b1955"},
	{56, "password", "78a07b6caf85fa"},
	{64, "Rough Consensus, and Running Code", "bb6ed30870b7f0e0"},
	{64, "kerberos", "6b65726265726f73"},
	{128, "kerberos", "6b65726265726f737b9b5b2b93132b93"},
	{168, "password", "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"},
	{192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY", "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"},
	{168, "Q", "518a54a215a8452a518a54a215a8452a518a54a215"},
	{168, "ba", "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"},
}

func TestNFold(t *testing.T) {
	//fmt.Printf("XXX Testing fold\n")
	for i, d := range foldTests {

		res := NFold([]byte(d.input), d.bits)
		if uint(len(res)*8) != d.bits {
			t.Errorf("Test %d failed. expected %d bits, but got %d\n", i, d.bits, len(res)*8)
			continue
		}
		if !bytes.HasPrefix(res, mustHexDecode(d.output)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, res, d.output)
			continue
		}
	}

}

// Data from rfc3962 appendix D
var aesKeyTests = []struct {
	iterations int
	usage      int
	password   string
	salt       string
	key        string
}{
	{1, cryptAes128CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "42263c6e89f4fc28b8df68ee09799f15"},
	{1, cryptAes256CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
	{2, cryptAes128CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "c651bf29e2300ac27fa469d693bdda13"},
	{2, cryptAes256CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
	{1200, cryptAes128CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "4c01cd46d632d01e6dbe230a01ed642a"},
	{1200, cryptAes256CtsHmac, "password", "ATHENA.MIT.EDUraeburn", "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"},
}

func TestAesKeyGeneration(t *testing.T) {
	//fmt.Printf("XXX Testing AES key generation\n")
	for i, d := range aesKeyTests {

		res := aeshmacKey(d.password, d.salt, d.iterations, d.usage)
		if !bytes.HasPrefix(res, mustHexDecode(d.key)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, res, d.key)
			continue
		}
	}

}
