package kerb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/jmckaskill/asn1"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
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
		return nil, ErrRemote{&errmsg}
	}

	var msgtype, usage int
	var repparam, encparam string
	var key key

	if r.tgt != nil {
		fmt.Printf("tgsReplyType\n")
		repparam = tgsReplyParam
		msgtype = tgsReplyType
		key = r.tgt.key
		usage = tgsReplySessionKey
		encparam = encTgsReplyParam
	} else {
		fmt.Printf("asReplyType\n")
		repparam = asReplyParam
		msgtype = asReplyType
		key = r.ckey
		usage = asReplyClientKey
		encparam = encAsReplyParam
	}

	// Decode reply body
	rep := kdcReply{}
	mustUnmarshal(data, &rep, repparam)
	fmt.Println("XXX 4")
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
	fmt.Printf("rep.ProtoVersion = %d\n", rep.ProtoVersion)
	fmt.Printf("rep.MsgType = %d\n", rep.MsgType)
	fmt.Printf("rep.Preauth = %v\n", rep.Preauth)
	fmt.Printf("rep.ClientRealm = %v\n", rep.ClientRealm)
	fmt.Printf("rep.Client = %v\n", rep.Client)
	fmt.Printf("rep.Ticket.Class = %v\n", rep.Ticket.Class)
	fmt.Printf("rep.Ticket.Tag = %v\n", rep.Ticket.Tag)
	fmt.Printf("rep.Ticket.IsCompound = %v\n", rep.Ticket.IsCompound)
	//fmt.Printf("rep.Ticket.Bytes = %v\n", rep.Ticket.Bytes)
	fmt.Printf("rep.Encrypted.Algo = %v\n", rep.Encrypted.Algo)
	fmt.Printf("rep.Encrypted.KeyVersion = %v\n", rep.Encrypted.KeyVersion)
	fmt.Printf("rep.Encrypted.Data = \n%s\n", hex.Dump(rep.Encrypted.Data))

	// Decode encrypted part
	enc := encryptedKdcReply{}
	edata := rep.Encrypted.Data
	if key != nil {
		edata = mustDecrypt(key, nil, rep.Encrypted.Algo, usage, rep.Encrypted.Data)
	}
	mustUnmarshal(edata, &enc, encparam)
	fmt.Printf("rep. decrypted.Key.Algo = %v\n", enc.Key.Algo)
	fmt.Printf("rep. decrypted.Key.Key = \n%s\n", hex.Dump(enc.Key.Key))
	fmt.Printf("rep. decrypted.LastRequests = %v\n", enc.LastRequests)
	fmt.Printf("rep. decrypted.Nonce = %v\n", enc.Nonce)
	fmt.Printf("rep. decrypted.ClientKeyExpiry = %v\n", enc.ClientKeyExpiry)
	fmt.Printf("rep. decrypted.Flags = %v\n", enc.Flags)
	fmt.Printf("rep. decrypted.AuthTime = %v\n", enc.AuthTime)
	fmt.Printf("rep. decrypted.From = %v\n", enc.From)
	fmt.Printf("rep. decrypted.Till = %v\n", enc.Till)
	fmt.Printf("rep. decrypted.RenewTill = %v\n", enc.RenewTill)
	fmt.Printf("rep. decrypted.ServiceRealm = %v\n", enc.ServiceRealm)
	fmt.Printf("rep. decrypted.Service = %v\n", enc.Service)
	fmt.Printf("rep. decrypted.Addresses = %v\n", enc.Addresses)
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

	// Try to interpret the ticket
	type KerbTicket struct {
		Version       int           `asn1:"explicit,tag:0"`
		Realm         string        `asn1:"explicit,tag:1"`
		PrincipalName principalName `asn1:"optional,explicit,tag:2"`
		Encrypted     encryptedData `asn1:"explicit,tag:3"`
	}
	kerbTicket := KerbTicket{}
	mustUnmarshal(rep.Ticket.FullBytes, &kerbTicket, "application,explicit,tag:1")
	fmt.Printf("Ticket.Version = %v\n", kerbTicket.Version)
	fmt.Printf("Ticket.Realm = %v\n", kerbTicket.Realm)
	fmt.Printf("Ticket.PrincipalName = %v\n", kerbTicket.PrincipalName)
	fmt.Printf("Ticket.Encrypted.Algo = %v\n", kerbTicket.Encrypted.Algo)
	fmt.Printf("Ticket.Encrypted.KeyVersion = %v\n", kerbTicket.Encrypted.KeyVersion)
	fmt.Printf("Ticket.Encrypted.Data = \n%s\n", hex.Dump(kerbTicket.Encrypted.Data))

	// Decrypt the ticket stuff
	type transitedEncoding struct {
		Type     int32  `asn1:"explicit,tag:0"`
		Contents []byte `asn1:"explicit,tag:1"`
	}
	type authorizationData struct {
		Type int32  `asn1:"explicit,tag:0"`
		Data []byte `asn1:"explicit,tag:1"`
	}
	type encryptedTicket struct {
		Flags             asn1.BitString      `asn1:"explicit,tag:0"`
		Key               encryptionKey       `asn1:"explicit,tag:1"`
		ClientRealm       string              `asn1:"explicit,tag:2"`
		ClientName        principalName       `asn1:"explicit,tag:3"`
		Transited         transitedEncoding   `asn1:"explicit,tag:4"`
		AuthTime          time.Time           `asn1:"generalized,explicit,tag:5"`
		From              time.Time           `asn1:"generalized,optional,explicit,tag:6"`
		Till              time.Time           `asn1:"generalized,explicit,tag:7"`
		RenewTill         time.Time           `asn1:"generalized,optional,explicit,tag:8"`
		Addresses         []address           `asn1:"optional,explicit,tag:9"`
		AuthorizationData []authorizationData `asn1:"optional,explicit,tag:10"`
	}
	encTicket := encryptedTicket{}
	etdata := kerbTicket.Encrypted.Data
	if key != nil {
		fmt.Printf("Decrypyting\n")
		etdata = mustDecrypt(key, nil, kerbTicket.Encrypted.Algo, ticketKey, kerbTicket.Encrypted.Data)
	} else {
		fmt.Printf("XXX NO key!\n")
	}
	fmt.Printf("unmarshaling\n")
	mustUnmarshal(etdata, &encTicket, "application,explicit,tag:3")
	fmt.Printf("Encrypted.Flags = %v\n", encTicket.Flags)
	fmt.Printf("Encrypted.Key = %v\n", encTicket.Key)
	fmt.Printf("Encrypted.ClientRealm = %v\n", encTicket.ClientRealm)
	fmt.Printf("Encrypted.ClientName = %v\n", encTicket.ClientName)
	fmt.Printf("Encrypted.Transited = %v\n", encTicket.Transited)
	fmt.Printf("Encrypted.AuthTime = %v\n", encTicket.AuthTime)
	fmt.Printf("Encrypted.From = %v\n", encTicket.From)
	fmt.Printf("Encrypted.Till = %v\n", encTicket.Till)
	fmt.Printf("Encrypted.RenewTill = %v\n", encTicket.RenewTill)
	fmt.Printf("Encrypted.Addresses = %v\n", encTicket.Addresses)
	fmt.Printf("Encrypted.AuthorizationData = %v\n", encTicket.AuthorizationData)

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	fmt.Println("XXX 1")
	must(enc.Nonce == r.nonce && enc.ServiceRealm == r.srealm)
	key = mustLoadKey(enc.Key.Algo, enc.Key.Key)

	return &Ticket{
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
	}, nil
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
