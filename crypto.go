package kerb

import (
	"bytes"
	"code.google.com/p/go.crypto/md4"
	// XXX Same base package as above?
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"unicode/utf16"
)

type key interface {
	// If algo is -1 then use the default
	Sign(algo, usage int, data ...[]byte) ([]byte, error)
	SignAlgo(usage int) int

	Encrypt(salt []byte, usage int, data ...[]byte) []byte
	Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error)
	EncryptAlgo(usage int) int

	Key() []byte
}

func mustSign(key key, algo, usage int, data ...[]byte) []byte {
	sign, err := key.Sign(algo, usage, data...)
	if err != nil {
		panic(err)
	}
	return sign
}

func mustDecrypt(key key, salt []byte, algo, usage int, data []byte) []byte {
	dec, err := key.Decrypt(salt, algo, usage, data)
	if err != nil {
		panic(err)
	}
	return dec
}

type rc4hmac struct {
	key []byte
}

// rc4HmacKey converts a UTF8 password into a key suitable for use with the
// rc4hmac.
func rc4HmacKey(password string) []byte {
	// Convert password from UTF8 to UTF16-LE
	s := make([]byte, 0)
	for _, r := range password {
		if r > 0x10000 {
			a, b := utf16.EncodeRune(r)
			s = append(s, byte(a), byte(a>>8), byte(b), byte(b>>8))
		} else {
			s = append(s, byte(r), byte(r>>8))
		}
	}

	h := md4.New()
	h.Write(s)
	return h.Sum(nil)
}

// RC4-HMAC has a few slight differences in the key usage values
func rc4HmacUsage(usage int) uint32 {
	switch usage {
	case asReplyClientKey:
		return 8
	case gssWrapSign:
		return 13
	}

	return uint32(usage)
}

func (c *rc4hmac) EncryptAlgo(usage int) int {
	switch usage {
	case gssWrapSeal, gssSequenceNumber:
		return cryptGssRc4Hmac
	}

	return cryptRc4Hmac
}

func (c *rc4hmac) Key() []byte {
	return c.key
}

func (c *rc4hmac) SignAlgo(usage int) int {
	switch usage {
	case gssWrapSign:
		return signGssRc4Hmac
	}

	// TODO: replace with RC4-HMAC checksum algorithm. For now we are
	// using the unkeyed RSA-MD5 checksum algorithm
	return signMd5
}

func unkeyedSign(algo, usage int, data ...[]byte) ([]byte, error) {
	var h hash.Hash

	switch algo {
	case signMd5:
		h = md5.New()
	case signMd4:
		h = md4.New()
	default:
		fmt.Println("XXX unkeySign")
		return nil, ErrProtocol
	}

	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil), nil

}

var signaturekey = []byte("signaturekey\x00")

func (c *rc4hmac) Sign(algo, usage int, data ...[]byte) ([]byte, error) {
	if algo != signGssRc4Hmac && algo != signRc4Hmac {
		return unkeyedSign(algo, usage, data...)
	}

	h := hmac.New(md5.New, c.key)
	h.Write(signaturekey)
	ksign := h.Sum(nil)

	chk := md5.New()
	binary.Write(chk, binary.LittleEndian, rc4HmacUsage(usage))
	for _, d := range data {
		chk.Write(d)
	}

	h = hmac.New(md5.New, ksign)
	h.Write(chk.Sum(nil))
	return h.Sum(nil), nil
}

func (c *rc4hmac) Encrypt(salt []byte, usage int, data ...[]byte) []byte {
	switch usage {
	case gssSequenceNumber:
		// salt is the checksum
		h := hmac.New(md5.New, c.key)
		binary.Write(h, binary.LittleEndian, uint32(0))
		h = hmac.New(md5.New, h.Sum(nil))
		h.Write(salt)
		r, _ := rc4.NewCipher(h.Sum(nil))
		for _, d := range data {
			r.XORKeyStream(d, d)
		}
		return bytes.Join(data, nil)

	case gssWrapSeal:
		// salt is the sequence number in big endian
		seqnum := binary.BigEndian.Uint32(salt)
		kcrypt := make([]byte, len(c.key))
		for i, b := range c.key {
			kcrypt[i] = b ^ 0xF0
		}
		h := hmac.New(md5.New, kcrypt)
		binary.Write(h, binary.LittleEndian, seqnum)
		r, _ := rc4.NewCipher(h.Sum(nil))
		for _, d := range data {
			r.XORKeyStream(d, d)
		}
		return bytes.Join(data, nil)
	}

	// Create the output vector, layout is 0-15 checksum, 16-23 random data, 24- actual data
	outsz := 24
	for _, d := range data {
		outsz += len(d)
	}
	out := make([]byte, outsz)
	io.ReadFull(rand.Reader, out[16:24])

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.New(md5.New, c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Fill in out[:16] with the checksum
	ch := hmac.New(md5.New, K1)
	ch.Write(out[16:24])
	for _, d := range data {
		ch.Write(d)
	}
	ch.Sum(out[:0])

	// Calculate the RC4 key using the checksum
	h3 := hmac.New(md5.New, K1)
	h3.Write(out[:16])
	K3 := h3.Sum(nil)

	// Encrypt out[16:] with 16:24 being random data and 24: being the
	// encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(out[16:24], out[16:24])

	dst := out[24:]
	for _, d := range data {
		r.XORKeyStream(dst[:len(d)], d)
		dst = dst[len(d):]
	}

	return out
}

func (c *rc4hmac) Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error) {
	switch usage {
	case gssSequenceNumber:
		if algo != cryptGssRc4Hmac && algo != cryptGssNone {
			fmt.Println("XXX rc4hmac, sequence number")
			return nil, ErrProtocol
		}

		return c.Encrypt(salt, usage, data), nil

	case gssWrapSeal:
		// GSS sealing uses an external checksum for integrity and
		// since RC4 is symettric we can just reencrypt the data
		if algo != cryptGssRc4Hmac {
			fmt.Println("XXX rc4hmac wrap seal")
			return nil, ErrProtocol
		}

		return c.Encrypt(salt, usage, data), nil
	}

	if algo != cryptRc4Hmac || len(data) < 24 {
		fmt.Printf("XXX rc4hmac algo/len algo=%v len=%d\n", algo, len(data))
		return nil, ErrProtocol
	}

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.New(md5.New, c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Calculate the RC4 key using the checksum
	h3 := hmac.New(md5.New, K1)
	h3.Write(data[:16])
	K3 := h3.Sum(nil)

	// Decrypt d.Data[16:] in place with 16:24 being random data and 24:
	// being the encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(data[16:], data[16:])

	// Recalculate the checksum using the decrypted data
	ch := hmac.New(md5.New, K1)
	ch.Write(data[16:])
	chk := ch.Sum(nil)

	// Check the input checksum
	if subtle.ConstantTimeCompare(chk, data[:16]) != 1 {
		fmt.Println("XXX rc4hmac checksum")
		return nil, ErrProtocol
	}

	return data[24:], nil
}

func fixparity(u uint64, expand bool) uint64 {
	for i := 7; i >= 0; i-- {
		// pull out this byte
		var b uint64
		if expand {
			b = (u >> uint(i*7)) & 0x7F
		} else {
			b = (u >> (uint(i*8) + 1)) & 0x7F
		}
		// compute parity
		p := b ^ (b >> 4)
		p &= 0x0F
		p = 0x9669 >> p
		// add in parity as lsb
		b = (b << 1) | (p & 1)
		// set that byte in output
		u &^= 0xFF << uint(i*8)
		u |= b << uint(i*8)
	}

	return u
}

func fixweak(u uint64) uint64 {
	switch u {
	case 0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
		0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E,
		0x011F011F010E010E, 0x1F011F010E010E01,
		0x01E001E001F101F1, 0xE001E001F101F101,
		0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01,
		0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
		0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E,
		0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1:
		u ^= 0xF0
	}

	return u
}

func desStringKey(password, salt string) []byte {
	blk := make([]byte, (len(password)+len(salt)+7)&^7)
	copy(blk, password)
	copy(blk[len(password):], salt)

	var u uint64
	for i := 0; i < len(blk); i += 8 {
		a := binary.BigEndian.Uint64(blk[i:])

		a = (a & 0x7F) |
			((a & 0x7F00) >> 1) |
			((a & 0x7F0000) >> 2) |
			((a & 0x7F000000) >> 3) |
			((a & 0x7F00000000) >> 4) |
			((a & 0x7F0000000000) >> 5) |
			((a & 0x7F000000000000) >> 6) |
			((a & 0x7F00000000000000) >> 7)

		if (i & 8) != 0 {
			a = ((a >> 1) & 0x5555555555555555) | ((a & 0x5555555555555555) << 1)
			a = ((a >> 2) & 0x3333333333333333) | ((a & 0x3333333333333333) << 2)
			a = ((a >> 4) & 0x0F0F0F0F0F0F0F0F) | ((a & 0x0F0F0F0F0F0F0F0F) << 4)
			a = ((a >> 8) & 0x00FF00FF00FF00FF) | ((a & 0x00FF00FF00FF00FF) << 8)
			a = ((a >> 16) & 0x0000FFFF0000FFFF) | ((a & 0x0000FFFF0000FFFF) << 16)
			a = (a >> 32) | (a << 32)
			a >>= 8
		}

		u ^= a
	}

	u = fixweak(fixparity(u, true))
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, u)

	b, _ := des.NewCipher(k)
	c := cipher.NewCBCEncrypter(b, k)
	c.CryptBlocks(blk, blk)

	u = binary.BigEndian.Uint64(blk[len(blk)-8:])
	u = fixweak(fixparity(u, false))
	binary.BigEndian.PutUint64(k, u)

	return k
}

// Translated to go from krb5 lib/crypto/krb/nfold.c
func NFold(in []byte, outbits uint) []byte {
	var a, b, c, lcm uint
	var thisByte, msbit uint

	/* the code below is more readable if I make these bytes
	   instead of bits */
	inbits := uint(len(in))
	outbits >>= 3

	/* first compute lcm(n,k) */

	a = outbits
	b = inbits

	for b != 0 {
		c = b
		b = a % b
		a = c
	}

	lcm = outbits * inbits / a

	/* now do the real work */

	out := make([]byte, outbits)
	thisByte = 0

	/* this will end up cycling through k lcm(k,n)/k times, which
	   is correct */
	for i := int(lcm - 1); i >= 0; i-- {
		/* compute the msbit in k which gets added into this byte */
		msbit = ( /* first, start with the msbit in the first, unrotated
		   byte */
		((inbits << 3) - 1) +
			/* then, for each byte, shift to the right for each
			   repetition */
			(((inbits << 3) + 13) * (uint(i) / inbits)) +
			/* last, pick out the correct byte within that
			   shifted repetition */
			((inbits - (uint(i) % inbits)) << 3)) % (inbits << 3)

		/* pull out the byte value itself */
		thisByte += (((uint(in[((inbits-1)-(msbit>>3))%inbits]) << 8) | (uint(in[((inbits)-(msbit>>3))%inbits]))) >> ((msbit & 7) + 1)) & 0xff

		/* do the addition */
		thisByte += uint(out[uint(i)%outbits])
		out[uint(i)%outbits] = byte(thisByte & 0xff)

		/*
			fmt.Printf("msbit[%d] = %d\tbyte = %02x\tsum = %03x\n\n", i, msbit,
				(((in[((inbits-1)-(msbit>>3))%inbits]<<8)|(in[((inbits)-(msbit>>3))%inbits]))>>((msbit&7)+1))&0xff, thisByte)
		*/

		/* keep around the carry bit, if any */
		thisByte >>= 8

		//fmt.Printf("carry=%d\n", thisByte)
	}

	/* if there's a carry bit left over, add it back in */
	if thisByte > 0 {
		for i := int(outbits - 1); i >= 0; i-- {
			/* do the addition */
			thisByte += uint(out[i])
			out[i] = byte(thisByte & 0xff)

			/* keep around the carry bit, if any */
			thisByte >>= 8
		}
	}
	return out
}

type descbc struct {
	key   []byte
	etype int
}

func (s *descbc) Sign(algo, usage int, data ...[]byte) ([]byte, error) {
	var h hash.Hash

	switch algo {
	case signGssDes:
		sz := 0
		for _, d := range data {
			sz += len(d)
		}
		sz = (sz + 7) &^ 7
		u := make([]byte, sz)
		v := u[:0]
		for _, d := range data {
			v = append(v, d...)
		}

		iv := [8]byte{}
		b, _ := des.NewCipher(s.key)
		c := cipher.NewCBCEncrypter(b, iv[:])
		c.CryptBlocks(u, u)
		return u[len(u)-8:], nil

	case signGssMd5Des:
		h = md5.New()
		for _, d := range data {
			h.Write(d)
		}
		return s.Sign(signGssDes, usage, h.Sum(nil))

	case signMd5Des:
		h = md5.New()
	case signMd4Des:
		h = md4.New()
	default:
		return unkeyedSign(algo, usage, data...)
	}

	var key [8]byte
	for i := 0; i < 8; i++ {
		key[i] = s.key[i] ^ 0xF0
	}

	chk := make([]byte, 24)
	io.ReadFull(rand.Reader, chk[:8])

	h.Write(chk[:8])
	for _, d := range data {
		h.Write(d)
	}
	h.Sum(chk[8:])

	iv := [8]byte{}
	b, _ := des.NewCipher(s.key)
	c := cipher.NewCBCEncrypter(b, iv[:])
	c.CryptBlocks(chk, chk)
	return chk, nil
}

func (s *descbc) SignAlgo(usage int) int {
	switch usage {
	case gssWrapSign:
		return signGssMd5Des
	}

	return signMd5Des
}

func (s *descbc) Encrypt(salt []byte, usage int, data ...[]byte) []byte {
	var h hash.Hash

	switch s.etype {
	case cryptDesCbcMd5:
		h = md5.New()
	case cryptDesCbcMd4:
		h = md4.New()
	default:
		panic("")
	}

	outsz := 8 + h.Size()
	for _, d := range data {
		outsz += len(d)
	}
	outsz = (outsz + 7) &^ 7
	out := make([]byte, outsz)

	io.ReadFull(rand.Reader, out[:8])

	v := out[8+h.Size():]
	for _, d := range data {
		n := copy(v, d)
		v = v[n:]
	}

	h.Write(out)
	h.Sum(out[:8])

	iv := [8]byte{}
	b, _ := des.NewCipher(s.key)
	c := cipher.NewCBCEncrypter(b, iv[:])
	c.CryptBlocks(out, out)

	return out
}

func (s *descbc) Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error) {
	var h hash.Hash

	switch algo {
	case cryptDesCbcMd5:
		h = md5.New()
	case cryptDesCbcMd4:
		h = md4.New()
	default:
		fmt.Println("XXX descbc algo")
		return nil, ErrProtocol
	}

	if (len(data) & 7) != 0 {
		fmt.Println("XXX descbc, len")
		return nil, ErrProtocol
	}

	iv := [8]byte{}
	b, _ := des.NewCipher(s.key)
	c := cipher.NewCBCDecrypter(b, iv[:])
	c.CryptBlocks(data, data)

	chk := make([]byte, h.Size())
	h.Write(data[:8])
	h.Write(chk) // Just need h.Size() zero bytes instead of the checksum
	h.Write(data[8+len(chk):])
	h.Sum(chk[:0])

	if subtle.ConstantTimeCompare(chk, data[8:8+len(chk)]) != 1 {
		fmt.Println("XXX descbc checksum")
		return nil, ErrProtocol
	}

	return data[8+len(chk):], nil
}

func (s *descbc) EncryptAlgo(usage int) int {
	switch usage {
	case gssWrapSeal, gssSequenceNumber:
		return cryptGssDes
	}

	return s.etype
}

func (s *descbc) Key() []byte {
	return s.key
}

type aeshmac struct {
	key   []byte
	etype int
}

func (s *aeshmac) Sign(algo, usage int, data ...[]byte) ([]byte, error) {
	fmt.Println("XXX aeshmac.Sign not yet supported")
	return nil, ErrProtocol
}
func (s *aeshmac) SignAlgo(usage int) int {
	return s.etype
}

func (s *aeshmac) Encrypt(salt []byte, usage int, data ...[]byte) []byte {
	h := hmac.New(sha1.New, s.key)
	const bb = 16
	const hashSize = 12
	outsz := bb + hashSize
	for _, d := range data {
		//fmt.Printf("len d %d\n", len(d))
		outsz += len(d)
	}
	//fmt.Printf("outsz %d\n", outsz)
	ln := outsz % bb
	if ln == 0 {
		ln = bb
	}
	//fmt.Printf("ln %d\n", ln)

	out := make([]byte, outsz)

	io.ReadFull(rand.Reader, out[:bb])
	v := out[bb+hashSize:]
	for _, d := range data {
		n := copy(v, d)
		v = v[n:]
	}

	h.Write(out)
	hash := h.Sum(nil)
	copy(out[bb:], hash[:hashSize])

	//fmt.Printf("Before encrypting\n")
	//fmt.Println(hex.Dump(out))

	iv := [bb]byte{}
	b, err := aes.NewCipher(s.key)
	if err != nil {
		panic(err)
	}
	c := cipher.NewCBCEncrypter(b, iv[:])

	//fmt.Printf("len of initial block %d\n", outsz-bb-ln)
	c.CryptBlocks(out[:outsz-bb-ln], out[:outsz-bb-ln])
	//fmt.Printf("After initial encrypting\n")
	//fmt.Println(hex.Dump(out))

	// Final block
	pn := [bb]byte{}
	cn := [bb]byte{}
	copy(pn[:], out[outsz-ln:outsz])

	// penultimate block
	pn1 := out[outsz-bb-ln : outsz-ln]
	cn1 := [bb]byte{}

	// Encrypt in order
	c.CryptBlocks(cn1[:], pn1[:])
	c.CryptBlocks(cn[:], pn[:])

	// Swap the order in the final data
	copy(out[outsz-bb-ln:outsz-ln], cn[:])
	copy(out[outsz-ln:outsz], cn1[:ln])

	//fmt.Printf("After encrypting last two blocks\n")
	//fmt.Println(hex.Dump(out))

	return out
}
func (s *aeshmac) Decrypt(salt []byte, algo, usage int, data []byte) ([]byte, error) {
	fmt.Printf("XXX in aeshmac.Decrypt\n")
	fmt.Printf("XXX s=%p\n", s)
	fmt.Printf("XXX s.key=%v\n", s.key)
	fmt.Printf("XXX data=%v\n", data)
	h := hmac.New(sha1.New, s.key)
	fmt.Printf("XXX new\n")
	const bb = 16
	const hashSize = 12
	insz := len(data)
	ln := insz % bb
	if ln == 0 {
		ln = bb
	}
	fmt.Printf("XXX lengths\n")

	iv := [bb]byte{}
	fmt.Printf("XXX about to NewCipher\n")
	b, _ := aes.NewCipher(s.key)
	fmt.Printf("XXX about to NewCBCDecrypter\n")
	c := cipher.NewCBCDecrypter(b, iv[:])

	fmt.Printf("Before decrypting\n")
	fmt.Println(hex.Dump(data))
	c.CryptBlocks(data[:insz-bb-ln], data[:insz-bb-ln])
	fmt.Printf("After decrypting first chunk\n")
	fmt.Println(hex.Dump(data))

	// Final block
	cn := [bb]byte{}
	copy(cn[:], data[insz-ln:insz])

	// penultimate block
	cn1 := data[insz-bb-ln : insz-ln]

	// Decrypt penulimate block first, without CBC
	dn := [bb]byte{}
	b.Decrypt(dn[:], cn1)

	// Append tail to cn
	copy(cn[ln:], dn[ln:])

	// Do normal CBC decryption, with flipped order
	pn := [bb]byte{}
	pn1 := [bb]byte{}
	c.CryptBlocks(pn1[:], cn[:])
	c.CryptBlocks(pn[:], cn1[:])

	// Now append to output and truncate
	copy(data[insz-bb-ln:insz-ln], pn1[:])
	copy(data[insz-ln:], pn[:ln])

	fmt.Printf("After decrypting final\n")
	fmt.Println(hex.Dump(data))

	// Verify checksum
	chk := make([]byte, hashSize)
	h.Write(data[:bb])
	h.Write(chk) // Just need h.Size() zero bytes instead of the checksum
	h.Write(data[bb+len(chk):])
	chk = h.Sum(nil)
	fmt.Printf("Computed hash: %s", hex.Dump(chk[:hashSize]))

	if subtle.ConstantTimeCompare(chk[:hashSize], data[bb:bb+hashSize]) != 1 {
		fmt.Println("XXX aeshmac checksum")
		return nil, ErrProtocol
	}

	return data[bb+hashSize:], nil
}
func (s *aeshmac) EncryptAlgo(usage int) int {
	return s.etype
}

func (s *aeshmac) Key() []byte {
	return s.key
}

// aesmacKey converts a UTF8 password+salt into a key suitable for use with the
// aeshmac.
func aeshmacKey(password, salt string, iterations, usage int) []byte {
	const bb = 16
	//fmt.Printf("XXX Generating key from password %s and salt %s\n", password, salt)
	// HACK
	var keyLen int
	// XXX RFC3962 is a little vague - 4096 looks right, but there's a
	// string-to-key parameter - where does that come from?
	// Looks like iteration count might come from the KDC - where/how?
	// ETYPE-INFO2 -> s2k-params for AES would list iteration count
	switch usage {
	case cryptAes128CtsHmac:
		keyLen = 16
	case cryptAes256CtsHmac:
		keyLen = 32
	}

	// XXX is this right?
	// https://tools.ietf.org/html/rfc3962 section 4 says:
	// tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength))
	// key = DK(tkey, "kerberos")
	hashFunc := sha1.New
	tkey := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLen, hashFunc)
	//fmt.Printf("XXX pbkdf2 result: %s", hex.Dump(tkey))
	constant := NFold([]byte("kerberos"), 128)
	//fmt.Printf("XXX const: %s", hex.Dump(constant))
	b, _ := aes.NewCipher(tkey)
	out := make([]byte, 32)
	copy(out, constant)
	b.Encrypt(out, out)
	b.Encrypt(out[bb:], out[:bb])
	//fmt.Printf("XXX output key: %s", hex.Dump(out))
	return out[:keyLen]
}

func generateKey(algo int, rand io.Reader) (key, error) {
	switch algo {
	case cryptRc4Hmac:
		data := [16]byte{}
		if _, err := io.ReadFull(rand, data[:]); err != nil {
			return nil, err
		}

		return loadKey(cryptRc4Hmac, data[:])

	case cryptDesCbcMd4, cryptDesCbcMd5:
		k := make([]byte, 8)
		if _, err := io.ReadFull(rand, k[1:]); err != nil {
			return nil, err
		}
		u := binary.BigEndian.Uint64(k)
		u = fixweak(fixparity(u, true))
		binary.BigEndian.PutUint64(k, u)
		return loadKey(algo, k)
	case cryptAes128CtsHmac, cryptAes256CtsHmac:
		fmt.Println("XXX generateKey with cryptAes256CtsHmac not yet supported")
		return nil, ErrProtocol
	}

	fmt.Println("XXX generateKey")
	return nil, ErrProtocol
}

func loadKey(algo int, key []byte) (key, error) {
	switch algo {
	case cryptRc4Hmac:
		return &rc4hmac{key}, nil
	case cryptDesCbcMd4, cryptDesCbcMd5:
		return &descbc{key, algo}, nil
	case cryptAes128CtsHmac, cryptAes256CtsHmac:
		return &aeshmac{key, algo}, nil
	}
	fmt.Println("XXX loadKey")
	return nil, ErrProtocol
}

func loadStringKey(algo int, pass, salt string) (key, error) {
	if len(pass) == 0 {
		fmt.Println("XXX loadStringKey no pass")
		return nil, ErrProtocol
	}

	switch algo {
	case cryptRc4Hmac:
		if len(salt) > 0 {
			fmt.Println("XXX loadStringKey salt")
			return nil, ErrProtocol
		}
		return &rc4hmac{rc4HmacKey(pass)}, nil

	case cryptDesCbcMd4, cryptDesCbcMd5:
		return &descbc{desStringKey(pass, salt), algo}, nil
	case cryptAes128CtsHmac, cryptAes256CtsHmac:
		return &aeshmac{aeshmacKey(pass, salt, 4096, algo), algo}, nil // XXX lookup iterations from kerb
	}

	fmt.Println("XXX loadStringKey fallthru")
	return nil, ErrProtocol
}

func mustGenerateKey(algo int, rand io.Reader) key {
	k, err := generateKey(algo, rand)
	if err != nil {
		panic(err)
	}
	return k
}

func mustLoadKey(algo int, key []byte) key {
	k, err := loadKey(algo, key)
	if err != nil {
		panic(err)
	}
	return k
}

func mustLoadStringKey(algo int, pass, salt string) key {
	k, err := loadStringKey(algo, pass, salt)
	if err != nil {
		panic(err)
	}
	return k
}
