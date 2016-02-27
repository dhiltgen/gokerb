package kerb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/jmckaskill/asn1"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

type request struct {
	cfg     *CredConfig
	client  principalName
	crealm  string
	ckey    key // only needed for AS requests when tgt == nil
	ckvno   int
	service principalName
	srealm  string
	till    time.Time
	flags   int
	tgt     *Ticket
	salt    []byte

	// Setup by request.do()
	nonce  uint32
	time   time.Time
	seqnum uint32
	sock   io.ReadWriteCloser
	proto  string

	// Temporary hack - this should be cleaned up
	keyPassword string
	keySalt     string
}

type KerbTicket struct {
	Version       int           `asn1:"explicit,tag:0"`
	Realm         string        `asn1:"explicit,tag:1"`
	PrincipalName principalName `asn1:"optional,explicit,tag:2"`
	Encrypted     encryptedData `asn1:"explicit,tag:3"`
}

var notill = asn1.RawValue{
	Bytes: []byte("19700101000000Z"),
	Class: 0,
	Tag:   24,
}

// sendRequest sends a single ticket request down the sock writer. If r.tgt is
// set this is a ticket granting service request, otherwise its an
// authentication service request. Note this does not use any random data, so
// resending will generate the exact same byte stream. This is needed with UDP
// connections such that if the remote receives multiple retries it discards
// the latters as replays.
func (r *request) sendRequest() (err error) {
	defer recoverMust(&err)

	body := kdcRequestBody{
		Client:       r.client,
		ServiceRealm: r.srealm,
		Service:      r.service,
		Flags:        flagsToBitString(r.flags),
		Till:         notill,
		Nonce:        r.nonce,
		Algorithms:   supportedAlgorithms,
	}

	if (r.till != time.Time{}) {
		body.Till.FullBytes = mustMarshal(r.till, "generalized")
	}

	bodydata := mustMarshal(body, "")

	reqparam := ""
	req := kdcRequest{
		ProtoVersion: kerberosVersion,
		Body:         asn1.RawValue{FullBytes: bodydata},
		// MsgType and Preauth filled out below
	}

	if r.tgt != nil {
		fmt.Printf("Sending tgsRequestType\n")
		// For TGS requests we stash an AP_REQ for the ticket granting
		// service (using the krbtgt) as a preauth.
		reqparam = tgsRequestParam
		req.MsgType = tgsRequestType

		calgo := r.tgt.key.SignAlgo(paTgsRequestChecksumKey)
		chk := mustSign(r.tgt.key, calgo, paTgsRequestChecksumKey, bodydata)

		auth := authenticator{
			ProtoVersion:   kerberosVersion,
			ClientRealm:    r.crealm,
			Client:         r.client,
			Microseconds:   r.time.Nanosecond() / 1000,
			SequenceNumber: r.seqnum,
			Time:           time.Unix(r.time.Unix(), 0).UTC(), // round to the nearest second
			Checksum:       checksumData{calgo, chk},
		}

		authdata := mustMarshal(auth, authenticatorParam)
		app := appRequest{
			ProtoVersion: kerberosVersion,
			MsgType:      appRequestType,
			Flags:        flagsToBitString(0),
			Ticket:       asn1.RawValue{FullBytes: r.tgt.ticket},
			Auth: encryptedData{
				Algo: r.tgt.key.EncryptAlgo(paTgsRequestKey),
				Data: r.tgt.key.Encrypt(nil, paTgsRequestKey, authdata),
			},
		}
		fmt.Printf("XXX Sending ticket:\n%s", hex.Dump(r.tgt.ticket))

		appdata := mustMarshal(app, appRequestParam)
		req.Preauth = []preauth{{paTgsRequest, appdata}}

	} else {
		fmt.Printf("Sending asRequestType\n")
		reqparam = asRequestParam
		req.MsgType = asRequestType

		// For AS requests we add a PA-ENC-TIMESTAMP preauth if we
		// have a key spefied. We won't on the first request so that
		// we can get a preauth error with the salt to use.
		if r.ckey != nil {
			// Use the sequence number as the microseconds in the
			// timestamp so that each one is guarenteed to be unique
			tsdata := mustMarshal(encryptedTimestamp{r.time, int(r.seqnum % 1000000)}, "")

			algo := r.ckey.EncryptAlgo(paEncryptedTimestampKey)
			edata := r.ckey.Encrypt(r.salt, paEncryptedTimestampKey, tsdata)
			enc := mustMarshal(encryptedData{algo, r.ckvno, edata}, "")

			req.Preauth = []preauth{{paEncryptedTimestamp, enc}}
		}
	}

	data := mustMarshal(req, reqparam)

	if r.proto == "tcp" {
		var bsz [4]byte
		binary.BigEndian.PutUint32(bsz[:], uint32(len(data)))
		mustWrite(r.sock, bsz[:])
	}

	if r.proto == "udp" && len(data) > maxUDPWrite {
		panic(io.ErrShortWrite)
	}

	mustWrite(r.sock, data)
	return nil
}

func (r *request) recvReply() (tkt *Ticket, err error) {
	fmt.Printf("XXX pass in recvReply: %s\n", r.keyPassword)
	defer recoverMust(&err)

	var data []byte

	switch r.proto {
	case "tcp":
		// TCP streams prepend a 32bit big endian size before each PDU
		bsz := [4]byte{}
		mustReadFull(r.sock, bsz[:])

		size := int(binary.BigEndian.Uint32(bsz[:]))
		fmt.Println("XXX 2")
		must(0 <= size && size <= maxPDUSize)

		data = make([]byte, size)
		mustReadFull(r.sock, data)

	case "udp":
		// UDP PDUs are packed in individual frames
		data = make([]byte, maxPDUSize)
		data = mustRead(r.sock, data)

	default:
		panic(ErrInvalidProto(r.proto))
	}

	fmt.Println("XXX 3")
	must(len(data) > 0)

	if (data[0] & 0x1F) == errorType {
		errmsg := errorMessage{}
		mustUnmarshal(data, &errmsg, errorParam)
		fmt.Printf("Error from server\n")
		fmt.Printf("    ProtoVersion: %d\n", errmsg.ProtoVersion)
		fmt.Printf("    MsgType: %d\n", errmsg.MsgType)
		fmt.Printf("    ClientTime: %v\n", errmsg.ClientTime)
		fmt.Printf("    ClientMicroseconds: %v\n", errmsg.ClientMicroseconds)
		fmt.Printf("    ServerTime: %v\n", errmsg.ServerTime)
		fmt.Printf("    ServerMicroseconds: %v\n", errmsg.ServerMicroseconds)
		fmt.Printf("    ErrorCode: %v\n", errmsg.ErrorCode)
		fmt.Printf("    ClientRealm: %v\n", errmsg.ClientRealm)
		fmt.Printf("    Client: %v\n", errmsg.Client)
		fmt.Printf("    ServiceRealm: %v\n", errmsg.ServiceRealm)
		fmt.Printf("    Service: %v\n", errmsg.Service)
		fmt.Printf("    ErrorText: %v\n", errmsg.ErrorText)
		fmt.Printf("    ErrorData: %v\n", errmsg.ErrorData)
		return nil, ErrRemote{&errmsg}
	}

	var msgtype, usage int
	var repparam, encparam string
	var key key

	// XXX DEBUG
	prefix := ""

	if r.tgt != nil {
		prefix = "TGS Reply"
		repparam = tgsReplyParam
		msgtype = tgsReplyType
		key = r.tgt.key
		usage = tgsReplySessionKey
		encparam = encTgsReplyParam
	} else {
		prefix = "AS Reply"
		repparam = asReplyParam
		msgtype = asReplyType
		key = r.ckey
		usage = asReplyClientKey
		encparam = encAsReplyParam
	}

	// Decode reply body
	rep := kdcReply{}
	mustUnmarshal(data, &rep, repparam)
	fmt.Println(prefix)
	must(rep.ProtoVersion == kerberosVersion && rep.MsgType == msgtype)
	must(rep.ClientRealm == r.crealm && nameEquals(rep.Client, r.client))

	// TGS doesn't use key versions as its using session keys
	if r.tgt == nil {
		// If we created the key from a keytab then we know the
		// version number, if we created it from plaintext then we use
		// the reply to find the key version

		if r.ckvno == 0 {
			r.ckvno = rep.Encrypted.KeyVersion
		} else {
			fmt.Println("XXX 5")
			must(r.ckvno == rep.Encrypted.KeyVersion)
		}
	}
	/* XXX Show what we got so far */
	fmt.Printf("%s: ProtoVersion = %d\n", prefix, rep.ProtoVersion)
	fmt.Printf("%s: MsgType = %d\n", prefix, rep.MsgType)
	fmt.Printf("%s: Preauth = %v\n", prefix, rep.Preauth)
	fmt.Printf("%s: ClientRealm = %v\n", prefix, rep.ClientRealm)
	fmt.Printf("%s: Client = %v\n", prefix, rep.Client)

	fmt.Printf("%s: Ticket.Class = %v\n", prefix, rep.Ticket.Class)
	fmt.Printf("%s: Ticket.Tag = %v\n", prefix, rep.Ticket.Tag)
	fmt.Printf("%s: Ticket.IsCompound = %v\n", prefix, rep.Ticket.IsCompound)
	//fmt.Printf("%s: Ticket.Bytes = \n%v\n", prefix, hex.Dump(rep.Ticket.Bytes)) // Dumped out in DumpPAC
	fmt.Printf("%s: Encrypted.Algo = %v\n", prefix, rep.Encrypted.Algo)
	fmt.Printf("%s: Encrypted.KeyVersion = %v\n", prefix, rep.Encrypted.KeyVersion)
	fmt.Printf("%s: Encrypted.Data = \n%s\n", prefix, hex.Dump(rep.Encrypted.Data))

	// Decode encrypted part
	enc := encryptedKdcReply{}
	edata := rep.Encrypted.Data
	if key != nil {
		edata = mustDecrypt(key, nil, rep.Encrypted.Algo, usage, rep.Encrypted.Data)
	}
	mustUnmarshal(edata, &enc, encparam)
	fmt.Printf("%s: decrypted.Key.Algo = %v\n", prefix, enc.Key.Algo)
	fmt.Printf("%s: decrypted.Key.Key = \n%s\n", prefix, hex.Dump(enc.Key.Key))
	fmt.Printf("%s: decrypted.LastRequests = %v\n", prefix, enc.LastRequests)
	fmt.Printf("%s: decrypted.Nonce = %v\n", prefix, enc.Nonce)
	fmt.Printf("%s: decrypted.ClientKeyExpiry = %v\n", prefix, enc.ClientKeyExpiry)
	fmt.Printf("%s: decrypted.Flags = %v\n", prefix, enc.Flags)
	fmt.Printf("%s: decrypted.AuthTime = %v\n", prefix, enc.AuthTime)
	fmt.Printf("%s: decrypted.From = %v\n", prefix, enc.From)
	fmt.Printf("%s: decrypted.Till = %v\n", prefix, enc.Till)
	fmt.Printf("%s: decrypted.RenewTill = %v\n", prefix, enc.RenewTill)
	fmt.Printf("%s: decrypted.ServiceRealm = %v\n", prefix, enc.ServiceRealm)
	fmt.Printf("%s: decrypted.Service = %v\n", prefix, enc.Service)
	fmt.Printf("%s: decrypted.Addresses = %v\n", prefix, enc.Addresses)
	/*
		Key             encryptionKey  `asn1:"explicit,tag:0"`
		LastRequests    []lastRequest  `asn1:"explicit,tag:1"`
		Nonce           uint32         `asn1:"explicit,tag:2"`
		ClientKeyExpiry time.Time      `asn1:"generalized,optional,explicit,tag:3"`
		Flags           asn1.BitString `asn1:"explicit,tag:4"`
		AuthTime        time.Time      `asn1:"generalized,explicit,tag:5"`
		From            time.Time      `asn1:"generalized,optional,explicit,tag:6"`
		Till            time.Time      `asn1:"generalized,explicit,tag:7"`
		RenewTill       time.Time      `asn1:"generalized,optional,explicit,tag:8"`
		ServiceRealm    string         `asn1:"general,explicit,tag:9"`
		Service         principalName  `asn1:"explicit,tag:10"`
		Addresses       []address      `asn1:"optional,explicit,tag:11"`
	*/

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	must(enc.Nonce == r.nonce && enc.ServiceRealm == r.srealm)
	key = mustLoadKey(enc.Key.Algo, enc.Key.Key)

	t := &Ticket{
		cfg:       r.cfg,
		client:    r.client,
		crealm:    r.crealm,
		service:   enc.Service,
		srealm:    enc.ServiceRealm,
		ticket:    rep.Ticket.FullBytes,
		till:      enc.Till,
		renewTill: enc.RenewTill,
		authTime:  enc.AuthTime,
		startTime: enc.From,
		flags:     bitStringToFlags(enc.Flags),
		key:       key,
	}
	//t.DumpPAC(nil)
	return t, nil
}

type Ticket struct {
	cfg       *CredConfig
	client    principalName
	crealm    string
	service   principalName
	srealm    string
	ticket    []byte
	till      time.Time
	renewTill time.Time
	authTime  time.Time
	startTime time.Time
	flags     int
	key       key
}

func DefaultDial(proto, realm string) (io.ReadWriteCloser, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, ErrInvalidProto(proto)
	}

	_, addrs, err := net.LookupSRV("kerberos", proto, realm)

	if err != nil {
		_, addrs, err = net.LookupSRV("kerberos-master", proto, realm)
		if err != nil {
			return nil, err
		}
	}

	var sock net.Conn

	for _, a := range addrs {
		addr := net.JoinHostPort(a.Target, strconv.Itoa(int(a.Port)))
		sock, err = net.Dial(proto, addr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	if proto == "udp" {
		// For datagram connections, we retry up to three times, then give up
		sock.SetReadDeadline(time.Now().Add(udpReadTimeout))
	}

	return sock, nil
}

type timeoutError interface {
	Timeout() bool
}

// do performs an AS_REQ (r.ckey != nil) or TGS_REQ (r.tgt != nil) returning a
// new ticket
func (r *request) do() (tkt *Ticket, err error) {
	//r.proto = "udp"
	r.proto = "tcp"
	r.sock = nil
	r.nonce = 0

	// Limit the number of retries before we give up and error out with
	// the last error
	for i := 0; i < 3; i++ {
		if r.sock == nil {
			if r.sock, err = r.cfg.dial(r.proto, r.srealm); err != nil {
				break
			}
		}

		if r.nonce == 0 {
			if err = binary.Read(r.cfg.rand(), binary.BigEndian, &r.nonce); err != nil {
				break
			}
			if err = binary.Read(r.cfg.rand(), binary.BigEndian, &r.seqnum); err != nil {
				break
			}
			// Reduce the entropy of the nonce to 31 bits to ensure it fits in a 4
			// byte asn.1 value. Active directory seems to need this.
			r.nonce >>= 1
			r.time = r.cfg.now().UTC()
		}

		// TODO what error do we get if the tcp socket has been closed underneath us
		err = r.sendRequest()

		if r.proto == "udp" && err == io.ErrShortWrite {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue
		} else if err != nil {
			break
		}

		tkt, err = r.recvReply()

		if err == nil {
			break

		} else if e, ok := err.(ErrRemote); r.proto == "udp" && ok && e.ErrorCode() == KRB_ERR_RESPONSE_TOO_BIG {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue

		} else if e, ok := err.(timeoutError); r.proto == "udp" && ok && e.Timeout() {
			// Try again for UDP timeouts.  Reuse nonce, time, and
			// seqnum values so if the multiple requests end up at
			// the server, the server will ignore the retries as
			// replays.
			continue

		} else {
			break
		}
	}

	if r.sock != nil {
		r.sock.Close()
		r.sock = nil
	}

	return tkt, err
}

// Principal returns the principal of the service the ticket is for
func (t *Ticket) Principal() string {
	return composePrincipal(t.service)
}

// Realm returns the realm of the service the ticket is for
func (t *Ticket) Realm() string {
	return t.srealm
}

// ExpiryTime returns the time at which the ticket expires
func (t *Ticket) ExpiryTime() time.Time {
	return t.till
}

// XXX Temporary until we can decode the ticket properly
func (t *Ticket) RawTicket() []byte {
	return t.ticket
}

// XXX replace with a routine to extract the real data and return some structure
func (t *Ticket) DumpPAC(servicePassword string) {
	fmt.Printf("Dumping ticket information including PAC\n")
	// Try to interpret the ticket
	kerbTicket := KerbTicket{}
	mustUnmarshal(t.ticket, &kerbTicket, "application,explicit,tag:1")
	fmt.Printf("Ticket.Version = %v\n", kerbTicket.Version)
	fmt.Printf("Ticket.Realm = %v\n", kerbTicket.Realm)
	fmt.Printf("Ticket.PrincipalName = %v\n", kerbTicket.PrincipalName)
	fmt.Printf("Ticket.Encrypted.Algo = %v\n", kerbTicket.Encrypted.Algo)
	fmt.Printf("Ticket.Encrypted.KeyVersion = %v\n", kerbTicket.Encrypted.KeyVersion)
	fmt.Printf("Ticket.Encrypted.Data = \n%s\n", hex.Dump(kerbTicket.Encrypted.Data))

	// The TGS ticket is encrypted with the machine password and salted with
	// the service principal.
	fmt.Printf("Attempting ticket decryption with algorithm %d\n", kerbTicket.Encrypted.Algo)
	//fmt.Printf("Attempting with machine secret %s\n", servicePassword)
	salt := ""
	if kerbTicket.Encrypted.Algo != cryptRc4Hmac {
		// TODO - this might be dumb... look at other algorithms that may or may not need salt
		salt = composePrincipal(kerbTicket.PrincipalName)
	}

	tkey, err := loadStringKey(kerbTicket.Encrypted.Algo, servicePassword, salt)
	if err != nil {
		fmt.Printf("Failed to generate Key using machine password and spn salt: %s\n", err)
		return
	}
	etdata, err := tkey.Decrypt(nil, kerbTicket.Encrypted.Algo, ticketKey, kerbTicket.Encrypted.Data)
	if err != nil {
		fmt.Printf("Failed to decrypt: %s\n", err)
		return
	}
	fmt.Printf("SUCCESS!!!\n")
	fmt.Printf("unmarshaling Ticket\n")
	encTicket := encryptedTicket{}
	mustUnmarshal(etdata, &encTicket, "application,explicit,tag:3")
	fmt.Printf("Encrypted.Flags = %v\n", encTicket.Flags)
	fmt.Printf("Encrypted.Key = %v\n", encTicket.Key)
	fmt.Printf("Encrypted.ClientRealm = %v\n", encTicket.ClientRealm)
	fmt.Printf("Encrypted.Client = %v\n", encTicket.Client)
	fmt.Printf("Encrypted.Transited = %v\n", encTicket.Transited)
	fmt.Printf("Encrypted.AuthTime = %v\n", encTicket.AuthTime)
	fmt.Printf("Encrypted.From = %v\n", encTicket.From)
	fmt.Printf("Encrypted.Till = %v\n", encTicket.Till)
	fmt.Printf("Encrypted.RenewTill = %v\n", encTicket.RenewTill)
	fmt.Printf("Encrypted.Addresses = %v\n", encTicket.Addresses)
	//fmt.Printf("Encrypted.AuthorizationData = %v\n", encTicket.AuthorizationData)
	for i, entry := range encTicket.Restrictions {
		fmt.Printf("Encrypted.AuthorizationData[%d] Type: %d\n%s\n", i, entry.Type, hex.Dump(entry.Data))
		if entry.Type == 1 {
			fmt.Printf("AD-IF-RELEVANT\n")
			ifRelevant := []restriction{}
			mustUnmarshal(entry.Data, &ifRelevant, "")
			for _, authData := range ifRelevant {
				fmt.Printf("\tType: %d\n%s\n", authData.Type, hex.Dump(authData.Data))
				if authData.Type == 128 { // WIN2K-PAC
					DecodePAC(authData)

				} // else ignore
			}
		}
		// Else ignored
	}
}

// TODO - REFACTOR THIS!!! - it's darn ugly
func DecodePAC(authData restriction) error {
	if authData.Type != 128 { // WIN2K-PAC
		return fmt.Errorf("Not WIN2K-PAC auth data: %d", authData.Type)
	}
	pac := PAC{}
	buf := bytes.NewReader(authData.Data)
	err := binary.Read(buf, binary.LittleEndian, &pac.Count)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &pac.Version)
	if err != nil {
		return err
	}
	// Now iterate through the buffers based on the count
	fmt.Printf("Detected %d PAC INFO buffers\n", pac.Count)
	for i := uint32(0); i < pac.Count; i++ {
		pib := PACInfoBuffer{}
		err = binary.Read(buf, binary.LittleEndian, &pib.Type)
		if err != nil {
			return err
		}
		err = binary.Read(buf, binary.LittleEndian, &pib.BufferSize)
		if err != nil {
			return err
		}
		err = binary.Read(buf, binary.LittleEndian, &pib.Offset)
		if err != nil {
			return err
		}
		pac.Buffers = append(pac.Buffers, pib)
		fmt.Printf("PAC[%d] type:%d size:%d offset:%d\n", i, pib.Type, pib.BufferSize, pib.Offset)
		switch pib.Type {
		case 1: // Logon information
			// Shift 4 bytes to compensate for the authData header
			DecodeLogonInfo(authData.Data[int(pib.Offset)-4 : int(pib.Offset)+int(pib.BufferSize)-4])
		}
		// TODO - other cases
	}
	// TODO continue dumping details
	return nil
}

// Pass in the byte slice already at right offset/length
func DecodeLogonInfo(data []byte) (*KerbValidationInfo, error) {
	fmt.Printf("Got buffer length: %d\n", len(data))
	li := KerbValidationInfo{}
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.LittleEndian, &li.LogonTime)
	if err != nil {
		return nil, err
	}
	fmt.Printf("LogonTime: %x\n", li.LogonTime)
	err = binary.Read(buf, binary.LittleEndian, &li.LogoffTime)
	if err != nil {
		return nil, err
	}
	fmt.Printf("LogoffTime: %x\n", li.LogoffTime)
	err = binary.Read(buf, binary.LittleEndian, &li.KickOffTime)
	if err != nil {
		return nil, err
	}
	fmt.Printf("KickOffTime: %x\n", li.KickOffTime)
	err = binary.Read(buf, binary.LittleEndian, &li.PasswordLastSet)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PasswordLastSet: %x\n", li.PasswordLastSet)
	err = binary.Read(buf, binary.LittleEndian, &li.PasswordCanChange)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PasswordCanChange: %x\n", li.PasswordCanChange)
	err = binary.Read(buf, binary.LittleEndian, &li.PasswordMustChange)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PasswordMustChange: %x\n", li.PasswordMustChange)
	// read in an RPC_UNICODE_STRING
	decodeString := func() (string, error) {
		var length uint16
		var maxLength uint16
		err := binary.Read(buf, binary.LittleEndian, &length)
		if err != nil {
			return "", err
		}
		err = binary.Read(buf, binary.LittleEndian, &maxLength)
		if err != nil {
			return "", err
		}
		fmt.Printf("XXX string: %x %x\n", length, maxLength)
		if length == 0 {
			return "", nil
		}
		wcharString := make([]uint16, length/2, length/2)
		err = binary.Read(buf, binary.LittleEndian, &wcharString)
		if err != nil {
			return "", err
		}
		return string(utf16.Decode(wcharString)), nil

	}
	li.EffectiveName, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.FullName, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.EffectiveName, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.FullName, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.LogonScript, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.ProfilePath, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.HomeDirectory, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.HomeDirectoryDrive, err = decodeString()
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.LittleEndian, &li.LogonCount)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &li.BadPasswordCount)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &li.UserId)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &li.PrimaryGroupId)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &li.GroupCount)
	if err != nil {
		return nil, err
	}
	groups := make([]uint32, li.GroupCount, li.GroupCount)
	err = binary.Read(buf, binary.LittleEndian, &groups)
	if err != nil {
		return nil, err
	}
	li.GroupIds = groups[:]
	err = binary.Read(buf, binary.LittleEndian, &li.UserFlags)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.LittleEndian, &li.UserSessionKey)
	if err != nil {
		return nil, err
	}
	li.LogonServer, err = decodeString()
	if err != nil {
		return nil, err
	}
	li.LogonDomainName, err = decodeString()
	if err != nil {
		return nil, err
	}

	return &li, nil
}

type KerbValidationInfo struct {
	LogonTime          uint64
	LogoffTime         uint64
	KickOffTime        uint64
	PasswordLastSet    uint64
	PasswordCanChange  uint64
	PasswordMustChange uint64
	EffectiveName      string
	FullName           string
	LogonScript        string
	ProfilePath        string
	HomeDirectory      string
	HomeDirectoryDrive string
	LogonCount         uint16
	BadPasswordCount   uint16
	UserId             uint32
	PrimaryGroupId     uint32
	GroupCount         uint32
	GroupIds           []uint32 //[size_is(GroupCount)]

	UserFlags       uint32
	UserSessionKey  [16]byte
	LogonServer     string
	LogonDomainName string
	/*
	   TODO - map remaining fields
	    PISID LogonDomainId // This one is kinda ugly, and we don't care, so I stopped here...
	    Reserved1 [2]uint32
	    UserAccountControl uint32
	    Reserved3 [7]uint32
	    SidCount uint32

	    [size_is(SidCount)]
	    PKERB_SID_AND_ATTRIBUTES ExtraSids;

	    PISID ResourceGroupDomainSid
	    ResourceGroupCount uint32

	    [size_is(ResourceGroupCount)]
	    PGROUP_MEMBERSHIP ResourceGroupIds
	*/
}

// TODO - move elsewhere
type PACInfoBuffer struct {
	Type       uint32 `asn1:"tag:0"`
	BufferSize uint32 `asn1:"tag:1"`
	Offset     uint64 `asn1:"tag:2"`
}

type PAC struct {
	Count   uint32
	Version uint32
	Buffers []PACInfoBuffer
}

// GenerateTicket generates a local ticket that a client can use to
// authenticate against this credential.
//
// This is provided for loopback clients and unit tests, and SHOULD NOT be
// used outside of those cases. For all other cases, tickets should be
// requested through the KDC.
func (c *Credential) GenerateTicket(client, crealm string, cfg *TicketConfig) (rtkt *Ticket, rerr error) {
	defer recoverMust(&rerr)

	crealm = strings.ToUpper(crealm)

	if cfg == nil {
		cfg = &DefaultTicketConfig
	}

	if c.key == nil {
		return nil, ErrPassword
	}

	etype := c.key.EncryptAlgo(ticketKey)
	tkey := mustGenerateKey(etype, c.cfg.rand())
	till := cfg.Till
	now := c.cfg.now().UTC()

	// round down to the nearest millisecond as the wire protocol doesn't allow higher res
	now = now.Add(-(time.Duration(now.Nanosecond()) % time.Millisecond))

	if till.IsZero() {
		// a long way in the future
		till = now.Add(200 * 356 * 24 * time.Hour)
	}

	etkt := encryptedTicket{
		Flags: flagsToBitString(cfg.Flags),
		Key: encryptionKey{
			Algo: etype,
			Key:  tkey.Key(),
		},
		ClientRealm: crealm,
		Client:      splitPrincipal(client),
		AuthTime:    now,
		Till:        till,
	}

	etktdata := mustMarshal(etkt, encTicketParam)

	tkt := ticket{
		ProtoVersion: kerberosVersion,
		Realm:        c.realm,
		Service:      c.principal,
		Encrypted: encryptedData{
			Algo: c.key.EncryptAlgo(ticketKey),
			Data: c.key.Encrypt(nil, ticketKey, etktdata),
		},
	}

	tktdata := mustMarshal(tkt, ticketParam)

	return &Ticket{
		cfg:       c.cfg,
		client:    etkt.Client,
		crealm:    crealm,
		service:   c.principal,
		srealm:    c.realm,
		ticket:    tktdata,
		till:      till,
		authTime:  now,
		startTime: now,
		flags:     cfg.Flags,
		key:       tkey,
	}, nil
}

func (c *Credential) mustGenerateTicket(client, crealm string, cfg *TicketConfig) *Ticket {
	tkt, err := c.GenerateTicket(client, crealm, cfg)
	if err != nil {
		panic(err)
	}
	return tkt
}
