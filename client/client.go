package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	//"fmt"
	"errors"

	"bytes"
	"encoding/json"
	"github.com/google/uuid"

	"filestore/userlib"

	// Optional.
	_ "strconv"
)

var (
	ErrUserExist          = errors.New("the User is already existed")
	ErrUserNotExist       = errors.New("the User doesn't existed")
	ErrUuidNotExist       = errors.New("the UUID doesn't exist")
	ErrContentTampered    = errors.New("content has been tampered with or the key doesn't match")
	ErrKeyNotMatch        = errors.New("the key doesn't match")
	ErrAuthenticityFailed = errors.New("the content is not issued by the given sources")
	ErrFileCollision      = errors.New("file collision")
	ErrFileNotFound       = errors.New("there is not such file in your namespace")
	ErrFileExist          = errors.New("the file is already existed")
	ErrPermissionDenied   = errors.New("auth err")
)

type Data struct {
	Content []byte
	Hmac    []byte
}
type Sign struct {
	Content  []byte
	SignByte []byte
}
type PKEData struct {
	Cipher    []byte
	SymCipher []byte
}

func wrapSymEnc(uuid uuid.UUID, Key []byte, v any) (data []byte, err error) {
	contentKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_ContentEncKey"))
	if err != nil {
		return nil, err
	}
	dataBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dataCipher := userlib.SymEnc(contentKey[:16], userlib.RandomBytes(16), dataBytes)
	return dataCipher, nil
}
func wrapHmac(uuid uuid.UUID, Key []byte, dataCipher []byte) (data []byte, err error) {
	hmacKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_HmacKey"))
	if err != nil {
		return nil, err
	}

	eval, err := userlib.HMACEval(hmacKey[:16], dataCipher)
	if err != nil {
		return nil, err
	}

	var msg Data
	msg.Hmac = eval
	msg.Content = dataCipher
	data, err = json.Marshal(&msg)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func wrapPKE(encKey userlib.PKEEncKey, v any) ([]byte, error) {
	symKey := userlib.RandomBytes(16)
	dataBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dataCipher := userlib.SymEnc(symKey, userlib.RandomBytes(16), dataBytes)
	enc, err := userlib.PKEEnc(encKey, symKey)
	if err != nil {
		return nil, err
	}
	var ret PKEData
	ret.Cipher = enc
	ret.SymCipher = dataCipher
	retBytes, err := json.Marshal(&ret)
	if err != nil {
		return nil, err
	}
	return retBytes, nil
}
func wrapSign(sk userlib.DSSignKey, data []byte) ([]byte, error) {
	sign, err := userlib.DSSign(sk, data)
	if err != nil {
		return nil, err
	}
	var signData Sign
	signData.Content = data
	signData.SignByte = sign
	signDataByte, err := json.Marshal(&signData)
	if err != nil {
		return nil, err
	}

	return signDataByte, nil
}
func unwrapPKE(uuid uuid.UUID, content []byte, decKey userlib.PKEDecKey, v any) error {
	var ret PKEData

	err := json.Unmarshal(content, &ret)
	if err != nil {
		return err
	}
	dec, err := userlib.PKEDec(decKey, ret.Cipher)
	if err != nil {
		return err
	}
	plainByte := userlib.SymDec(dec, ret.SymCipher)

	err = json.Unmarshal(plainByte, v)
	if err != nil {
		return err
	}
	return nil
}
func unwrapSymDec(uuid uuid.UUID, content []byte, Key []byte, v any) error {
	contentKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_ContentEncKey"))
	if err != nil {
		return err
	}
	contentByte := userlib.SymDec(contentKey[:16], content)
	err = json.Unmarshal(contentByte, v)
	if err != nil {
		return err
	}
	return nil
}
func unwrapHmac(uuid uuid.UUID, content []byte, Key []byte) ([]byte, error) {
	hmacKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_HmacKey"))
	if err != nil {
		return nil, err
	}
	var data Data
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}

	hmac, err := userlib.HMACEval(hmacKey[:16], data.Content)
	equal := userlib.HMACEqual(hmac, data.Hmac)
	if !equal {
		return nil, ErrKeyNotMatch
	}

	return data.Content, nil
}
func unwaapSign(uuid uuid.UUID, owner string) ([]byte, error) {

	value, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return nil, ErrUuidNotExist
	}
	var signData Sign
	err := json.Unmarshal(value, &signData)
	if err != nil {
		return nil, err
	}
	verifyKey, ok := userlib.KeystoreGet(owner + "_DSVerifyKey")
	if !ok {
		return nil, ErrUserNotExist
	}

	err = userlib.DSVerify(verifyKey, signData.Content, signData.SignByte)
	if err != nil {
		return nil, err
	}

	return signData.Content, nil
}

func GetData(uuid uuid.UUID, Key []byte, v any) error {
	value, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return ErrUuidNotExist
	}
	hmac, err := unwrapHmac(uuid, value, Key)
	if err != nil {
		return err
	}
	err = unwrapSymDec(uuid, hmac, Key, v)
	if err != nil {
		return err
	}
	return nil
}
func StoreData(uuid uuid.UUID, Key []byte, v any) (err error) {
	//contentKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_ContentEncKey"))
	//if err != nil {
	//	return err
	//}
	//
	//hmacKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_HmacKey"))
	//if err != nil {
	//	return err
	//}
	//
	//dataBytes, err := json.Marshal(v)
	//dataCipher := userlib.SymEnc(contentKey[:16], userlib.RandomBytes(16), dataBytes)
	//
	//eval, err := userlib.HMACEval(hmacKey[:16], dataCipher)
	//if err != nil {
	//	return err
	//}
	//
	//var msg Data
	//msg.Hmac = eval
	//msg.Content = dataCipher
	//data, err := json.Marshal(&msg)
	//
	//if err != nil {
	//	return err
	//}
	//userlib.DatastoreSet(uuid, data)
	//return nil
	enc, err := wrapSymEnc(uuid, Key, &v)
	if err != nil {
		return err
	}
	hmac, err := wrapHmac(uuid, Key, enc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid, hmac)
	return nil
}
func GetSignData(uuid uuid.UUID, owner string, Key []byte, v any) error {
	//
	//contentKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_ContentEncKey"))
	//if err != nil {
	//	return err
	//}
	//
	//hmacKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_HmacKey"))
	//if err != nil {
	//	return err
	//}
	//
	//value, ok := userlib.DatastoreGet(uuid)
	//if !ok {
	//	return ErrUuidNotExist
	//}
	//var signData Sign
	//err = json.Unmarshal(value, &signData)
	//if err != nil {
	//	return err
	//}
	//verifyKey, ok := userlib.KeystoreGet(owner + "_DSVerifyKey")
	//if !ok {
	//	return ErrUserNotExist
	//}
	//
	//err = userlib.DSVerify(verifyKey, signData.Content, signData.SignByte)
	//if err != nil {
	//	return err
	//}
	//var data Data
	//err = json.Unmarshal(signData.Content, &data)
	//if err != nil {
	//	return err
	//}
	//
	//hmac, err := userlib.HMACEval(hmacKey[:16], data.Content)
	//equal := userlib.HMACEqual(hmac, data.Hmac)
	//if !equal {
	//	return ErrKeyNotMatch
	//}
	//
	//contentByte := userlib.SymDec(contentKey[:16], data.Content)
	//err = json.Unmarshal(contentByte, v)
	//if err != nil {
	//	return err
	//}
	//
	//return nil
	sign, err := unwaapSign(uuid, owner)
	if err != nil {
		return err
	}

	hmac, err := unwrapHmac(uuid, sign, Key)
	if err != nil {
		return err
	}
	err = unwrapSymDec(uuid, hmac, Key, v)
	if err != nil {
		return err
	}
	return nil
}
func StoreSignData(uuid uuid.UUID, sk userlib.DSSignKey, Key []byte, v any) (err error) {
	//contentKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_ContentEncKey"))
	//if err != nil {
	//	return err
	//}
	//
	//hmacKey, err := userlib.HashKDF(Key[:16], []byte(uuid.String()+"_HmacKey"))
	//if err != nil {
	//	return err
	//}
	//
	//dataBytes, err := json.Marshal(v)
	//dataCipher := userlib.SymEnc(contentKey[:16], userlib.RandomBytes(16), dataBytes)
	//
	//eval, err := userlib.HMACEval(hmacKey[:16], dataCipher)
	//if err != nil {
	//	return err
	//}
	//
	//var msg Data
	//msg.Hmac = eval
	//msg.Content = dataCipher
	//data, err := json.Marshal(&msg)
	//if err != nil {
	//	return err
	//}
	//sign, err := userlib.DSSign(sk, data)
	//if err != nil {
	//	return err
	//}
	//var signData Sign
	//signData.Content = data
	//signData.SignByte = sign
	//signDataByte, err := json.Marshal(&signData)
	//if err != nil {
	//	return err
	//}
	//
	//userlib.DatastoreSet(uuid, signDataByte)
	//return nil
	enc, err := wrapSymEnc(uuid, Key, &v)
	if err != nil {
		return err
	}
	hmac, err := wrapHmac(uuid, Key, enc)
	if err != nil {
		return err
	}
	signDataByte, err := wrapSign(sk, hmac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid, signDataByte)
	return nil
}
func StorePKEData(uuid uuid.UUID, Key userlib.PKEEncKey, SignKey userlib.DSSignKey, v any) (err error) {
	pke, err := wrapPKE(Key, v)
	if err != nil {
		return err
	}
	sign, err := wrapSign(SignKey, pke)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid, sign)
	return nil
}

func GetPKEData(uuid uuid.UUID, owner string, Key userlib.PKEDecKey, v any) error {
	sign, err := unwaapSign(uuid, owner)
	if err != nil {
		return err
	}
	err = unwrapPKE(uuid, sign, Key, v)
	if err != nil {
		return err
	}
	return nil
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username     string
	PKEDecKey    userlib.PKEDecKey
	DSSignKey    userlib.DSSignKey
	passwordHash []byte
	//SharedFiles map[string]uuid.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

//type file struct {
//	id map[string]uuid.UUID
//	file
//}

// NOTE: The following methods have toy (insecure!) implementations.

// user part
func InitUser(username string, password string) (userdataptr *User, err error) {
	_, exist := userlib.KeystoreGet(username + "_PKEEncKey")
	if exist {
		return nil, ErrUserExist
	}

	nameHash := userlib.Hash([]byte(username))
	nameUuid, err := uuid.FromBytes(nameHash[:16])
	if err != nil {
		return nil, err
	}

	var userdata User
	userdata.Username = username
	salt := userlib.RandomBytes(32)
	saltHash := userlib.Hash([]byte(username + "_salt"))
	saltUuid, err := uuid.FromBytes(saltHash[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(saltUuid, salt)

	passwordHash := userlib.Argon2Key([]byte(password), salt, 64)

	//pkEncKey, err := userlib.HashKDF(passwordHash, []byte("pkeEnc"))
	//if err != nil {
	//	return nil, err
	//}

	//userEnc, err := userlib.HashKDF(passwordHash[:16], []byte("userEnc"))
	//userlib.DebugMsg(string(userEnc))
	//if err != nil {
	//	return nil, err
	//}
	//
	//hmacKey, err := userlib.HashKDF(passwordHash[:16], []byte("hmacKey"))
	//if err != nil {
	//	return nil, err
	//}

	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()

	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"_PKEEncKey", pk)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"_DSVerifyKey", verifyKey)
	if err != nil {
		return nil, err
	}

	userdata.PKEDecKey = sk
	userdata.DSSignKey = signKey

	//userBytes, err := json.Marshal(&userdata)
	//userCipher := userlib.SymEnc(userEnc[:16], userlib.RandomBytes(16), userBytes)/**/
	//err = StoreWithHmac(nameUuid, hmacKey[:16], userCipher)

	//err = StoreData(nameUuid, passwordHash, &userdata)
	userdata.passwordHash = passwordHash
	err = StoreSignData(nameUuid, signKey, passwordHash, &userdata)
	if err != nil {
		return nil, err
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	_, exist := userlib.KeystoreGet(username + "_PKEEncKey")
	if !exist {
		return nil, ErrUserNotExist
	}

	var userdata User

	nameHash := userlib.Hash([]byte(username))
	nameUuid, err := uuid.FromBytes(nameHash[:16])
	if err != nil {
		return nil, err
	}

	saltHash := userlib.Hash([]byte(username + "_salt"))
	saltUuid, err := uuid.FromBytes(saltHash[:16])
	if err != nil {
		return nil, err
	}
	salt, ok := userlib.DatastoreGet(saltUuid)

	if !ok {
		return nil, ErrContentTampered
	}
	passwordHash := userlib.Argon2Key([]byte(password), salt, 64)
	//userEnc, err := userlib.HashKDF(passwordHash[:16], []byte("userEnc"))
	//if err != nil {
	//	return nil, err
	//}
	//
	//hmacKey, err := userlib.HashKDF(passwordHash[:16], []byte("hmacKey"))
	//if err != nil {
	//	return nil, err
	//}
	//userCipher, err := GetWithHmac(nameUuid, hmacKey[:16])
	err = GetSignData(nameUuid, username, passwordHash, &userdata)
	//err = GetData(nameUuid, passwordHash, &userdata)
	if err != nil {
		return nil, err
	}

	//userByte := userlib.SymDec(userEnc[:16], userCipher)
	//err = json.Unmarshal(userByte, &userdata)
	//if err != nil {
	//	return nil, err
	//}
	userdata.passwordHash = passwordHash
	userdataptr = &userdata
	return userdataptr, nil
}

// filedata part
type FileHandler struct {
	FileID    uuid.UUID
	Key       []byte
	fileChain []uuid.UUID
	rootPriv  bool
}

// FileRoot user + filename + "owner" -> hash ->  16bit ->  uuid,
type RootFile struct {
	FileID uuid.UUID
	Key    []byte
	//id                   map[string]uuid.UUID //store [Name]DerivedShareFile
	DerivedShareFileUUID map[string]uuid.UUID
	//DerivedShareFileKey  []byte
}

// random uuid pass by the Sharer
type signedShareFileChain struct {
	DerivedShareFileUUID uuid.UUID
	DerivedShareFileKey  []byte
}

// SharedFile user + filename + "shared" -> hash ->  16bit ->  uuid (wrap with the owner's pk sign)
type SharedFile struct {
	SignedShareFileChainUUID uuid.UUID
	Sharer                   string
}

// random uuid ack through signedChain
type DerivedShareFile struct {
	FileID uuid.UUID
	Key    []byte
}
type shareChain struct {
}

func newFileHandler(fileID uuid.UUID, key []byte) (filePointer *FileHandler, err error) {
	file := FileHandler{FileID: fileID, Key: key}
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(fileID)
	if !ok {
		file.fileChain = make([]uuid.UUID, 0)
		err := StoreData(fileID, key, &file.fileChain)
		if err != nil {
			return nil, err
		}
		return &file, nil
	}

	err = GetData(fileID, key, &file.fileChain)
	if err != nil {
		return nil, err
	}

	//return &file, nil
	return &file, nil
}
func (h FileHandler) Owned() bool {
	return h.rootPriv
}
func (h FileHandler) SetOwned(o bool) {
	h.rootPriv = o
}
func (h FileHandler) AppendFile(contents []byte) error {
	//size = len(h.fileChain)
	blockID := uuid.New()
	h.fileChain = append(h.fileChain, blockID)
	err := StoreData(h.FileID, h.Key, &h.fileChain)
	if err != nil {
		return err
	}
	err = StoreData(blockID, h.Key, contents)
	if err != nil {
		return err
	}
	return nil
}
func (h FileHandler) deleteAll() error {
	for _, fileBlockUUID := range h.fileChain {
		userlib.DatastoreSet(fileBlockUUID, []byte(""))
	}
	h.fileChain = make([]uuid.UUID, 0)
	err := StoreData(h.FileID, h.Key, &h.fileChain)
	if err != nil {
		return err
	}
	return nil
}
func (h FileHandler) OverWrite(contents []byte) error {
	//size = len(h.fileChain)
	blockID := uuid.New()
	err := h.deleteAll()
	if err != nil {
		return err
	}

	h.fileChain = make([]uuid.UUID, 0)
	h.fileChain = append(h.fileChain, blockID)
	err = StoreData(h.FileID, h.Key, &h.fileChain)
	if err != nil {
		return err
	}
	err = StoreData(blockID, h.Key, &contents)
	if err != nil {
		return err
	}
	return nil
}
func (h FileHandler) ReadFile() (contents []byte, err error) {
	var block []byte
	var jar [][]byte
	jar = make([][]byte, 0)
	for _, fileBlockUUID := range h.fileChain {
		err := GetData(fileBlockUUID, h.Key, &block)
		if err != nil {
			return nil, err
		}
		jar = append(jar, block)
	}
	contents = bytes.Join(jar, []byte(""))
	return contents, nil
}
func (h FileHandler) ChangeFileKey(newFileID uuid.UUID, key []byte) error {
	var block string

	newChain := make([]uuid.UUID, 0)
	for _, fileBlockUUID := range h.fileChain {
		newBlockID := uuid.New()
		err := GetData(fileBlockUUID, h.Key, &block)
		if err != nil {
			return err
		}
		newChain = append(newChain, newBlockID)
		err = StoreData(newBlockID, key, &block)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileBlockUUID, []byte(""))
	}
	h.fileChain = newChain
	err := StoreData(newFileID, key, &h.fileChain)
	if err != nil {
		return err
	}
	h.Key = key
	return nil
}

// func (userdata *User) getOwnFile() (handler *FileHandler, err error) {
//
// }
//
// func (userdata *User) getSharedFile() (handler *FileHandler, err error) {
//
// }
func (userdata *User) createNewFile(fileId uuid.UUID) (handler *FileHandler, err error) {
	key := userlib.RandomBytes(16)
	fileUUID := uuid.New()
	handler, err = newFileHandler(fileUUID, key)
	handler.SetOwned(true)
	if err != nil {
		return nil, err
	}
	//var derivedFile DerivedShareFile
	//derivedFile.FileID = fileUUID
	//derivedFile.Key = key
	//derivedFileEncKey := userlib.RandomBytes(16)
	//derivedFileUUID := uuid.New()
	//err = StoreData(derivedFileUUID, derivedFileEncKey, &derivedFile)
	//if err != nil {
	//	return nil, err
	//}

	var root RootFile
	root.FileID = fileUUID
	root.Key = key
	root.DerivedShareFileUUID = make(map[string]uuid.UUID)
	//root.DerivedShareFileUUID = derivedFileUUID
	//root.DerivedShareFileKey = derivedFileEncKey

	err = StoreData(fileId, userdata.passwordHash, root)
	if err != nil {
		return nil, err
	}

	return handler, nil
}

var (
	FileNotCreated  = uint8(0)
	RootPrivilege   = uint8(1)
	SharedPrivilege = uint8(2)
)

func (userdata *User) CheckFileStatus(filename string) (value []byte, statusCode uint8, err error) {
	storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
	if err != nil {
		return nil, 100, err
	}
	sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
	if err != nil {
		return nil, 100, err
	}
	value, rootOK := userlib.DatastoreGet(storageUUID)
	sharedValue, sharedOK := userlib.DatastoreGet(sharedUUID)
	if rootOK && sharedOK {
		return nil, 100, ErrFileCollision
	}
	if rootOK {
		return value, RootPrivilege, nil
	}
	if sharedOK {
		return sharedValue, SharedPrivilege, nil
	}
	return nil, FileNotCreated, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return err
	}
	if status == FileNotCreated {
		storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
		if err != nil {
			return err
		}
		handler, err := userdata.createNewFile(storageUUID)
		if err != nil {
			return err
		}
		err = handler.AppendFile(content)
		if err != nil {
			return err
		}

	} else if status == RootPrivilege {
		storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
		if err != nil {
			return err
		}
		var root RootFile
		err = GetData(storageUUID, userdata.passwordHash, &root)
		if err != nil {
			return err
		}
		handler, err := newFileHandler(root.FileID, root.Key)
		if err != nil {
			return err
		}
		err = handler.OverWrite(content)
		if err != nil {
			return err
		}
	} else if status == SharedPrivilege {
		sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
		if err != nil {
			return err
		}
		var shared SharedFile
		err = GetData(sharedUUID, userdata.passwordHash, &shared)
		if err != nil {
			return err
		}
		var chain signedShareFileChain
		err = GetPKEData(shared.SignedShareFileChainUUID, shared.Sharer, userdata.PKEDecKey, &chain)
		if err != nil {
			return err
		}
		var fileInfo DerivedShareFile
		err = GetData(chain.DerivedShareFileUUID, chain.DerivedShareFileKey, &fileInfo)
		if err != nil {
			return err
		}
		handler, err := newFileHandler(fileInfo.FileID, fileInfo.Key)
		if err != nil {
			return err
		}
		err = handler.OverWrite(content)
		if err != nil {
			return err
		}
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return err
	}

	if status == FileNotCreated {
		return ErrFileNotFound
	} else if status == RootPrivilege {
		storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
		if err != nil {
			return err
		}
		var root RootFile
		err = GetData(storageUUID, userdata.passwordHash, &root)
		if err != nil {
			return err
		}
		handler, err := newFileHandler(root.FileID, root.Key)
		if err != nil {
			return err
		}
		err = handler.AppendFile(content)
		if err != nil {
			return err
		}
	} else if status == SharedPrivilege {
		sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
		if err != nil {
			return err
		}
		var shared SharedFile
		err = GetData(sharedUUID, userdata.passwordHash, &shared)
		if err != nil {
			return err
		}
		var chain signedShareFileChain
		err = GetPKEData(shared.SignedShareFileChainUUID, shared.Sharer, userdata.PKEDecKey, &chain)
		if err != nil {
			return err
		}
		var fileInfo DerivedShareFile
		err = GetData(chain.DerivedShareFileUUID, chain.DerivedShareFileKey, &fileInfo)
		if err != nil {
			return err
		}
		handler, err := newFileHandler(fileInfo.FileID, fileInfo.Key)
		if err != nil {
			return err
		}
		err = handler.AppendFile(content)
		if err != nil {
			return err
		}
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return nil, err
	}

	if status == FileNotCreated {
		return nil, ErrFileNotFound
	} else if status == RootPrivilege {
		storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
		if err != nil {
			return nil, err
		}
		var root RootFile
		err = GetData(storageUUID, userdata.passwordHash, &root)
		if err != nil {
			return nil, err
		}
		handler, err := newFileHandler(root.FileID, root.Key)
		if err != nil {
			return nil, err
		}
		fileByte, err := handler.ReadFile()
		if err != nil {
			return nil, err
		}
		return fileByte, nil
	} else if status == SharedPrivilege {
		sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
		if err != nil {
			return nil, err
		}
		var shared SharedFile
		err = GetData(sharedUUID, userdata.passwordHash, &shared)
		if err != nil {
			return nil, err
		}
		var chain signedShareFileChain
		err = GetPKEData(shared.SignedShareFileChainUUID, shared.Sharer, userdata.PKEDecKey, &chain)
		if err != nil {
			return nil, err
		}
		var fileInfo DerivedShareFile
		err = GetData(chain.DerivedShareFileUUID, chain.DerivedShareFileKey, &fileInfo)
		if bytes.Equal(fileInfo.Key, []byte("")) {
			return nil, ErrPermissionDenied
		}
		//userlib.DebugMsg(chain.DerivedShareFileUUID.String())

		if err != nil {
			return nil, err
		}
		handler, err := newFileHandler(fileInfo.FileID, fileInfo.Key)
		if err != nil {
			return nil, err
		}
		fileByte, err := handler.ReadFile()
		if err != nil {
			return nil, err
		}

		userlib.DebugMsg(userdata.Username + "use:" + fileInfo.FileID.String() + "to access: " + filename)
		return fileByte, nil
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	invitationPtr = uuid.New()
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return uuid.Nil, err
	}

	if status == FileNotCreated {
		return uuid.Nil, ErrFileNotFound
	} else if status == RootPrivilege {
		storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
		if err != nil {
			return uuid.Nil, err
		}
		var root RootFile
		err = GetData(storageUUID, userdata.passwordHash, &root)
		if err != nil {
			return uuid.Nil, err
		}
		var derivedFile DerivedShareFile
		derivedFile.FileID = root.FileID
		derivedFile.Key = root.Key

		derivedFileUUID := uuid.New()

		derivedFileEncKey, err := userlib.HashKDF(userdata.passwordHash[:16],
			[]byte(derivedFileUUID.String()))
		if err != nil {
			return uuid.Nil, err
		}

		err = StoreData(derivedFileUUID, derivedFileEncKey, &derivedFile)
		if err != nil {
			return uuid.Nil, err
		}
		root.DerivedShareFileUUID[recipientUsername+"_"+filename] = derivedFileUUID

		var chain signedShareFileChain
		chain.DerivedShareFileUUID = derivedFileUUID
		chain.DerivedShareFileKey = derivedFileEncKey

		recipientPKE, ok := userlib.KeystoreGet(recipientUsername + "_PKEEncKey")
		if !ok {
			return uuid.Nil, ErrUserNotExist
		}

		err = StorePKEData(invitationPtr, recipientPKE, userdata.DSSignKey, &chain)
		if err != nil {
			return uuid.Nil, err
		}

		err = StoreData(storageUUID, userdata.passwordHash, &root)
		if err != nil {
			return uuid.Nil, err
		}
		return invitationPtr, nil
	} else if status == SharedPrivilege {
		sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
		if err != nil {
			return uuid.Nil, err
		}
		var shared SharedFile
		err = GetData(sharedUUID, userdata.passwordHash, &shared)
		if err != nil {
			return uuid.Nil, err
		}
		var chain signedShareFileChain
		err = GetPKEData(shared.SignedShareFileChainUUID, shared.Sharer, userdata.PKEDecKey, &chain)
		if err != nil {
			return uuid.Nil, err
		}
		var recipientChain signedShareFileChain
		recipientChain.DerivedShareFileUUID = chain.DerivedShareFileUUID
		recipientChain.DerivedShareFileKey = chain.DerivedShareFileKey

		recipientPKE, ok := userlib.KeystoreGet(recipientUsername + "_PKEEncKey")
		if !ok {
			return uuid.Nil, ErrUserNotExist
		}

		err = StorePKEData(invitationPtr, recipientPKE, userdata.DSSignKey, &recipientChain)
		if err != nil {
			return uuid.Nil, err
		}

	}
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return err
	}

	if status != FileNotCreated {
		return ErrFileExist
	}

	var chain signedShareFileChain
	err = GetPKEData(invitationPtr, senderUsername, userdata.PKEDecKey, &chain)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(chain.DerivedShareFileUUID)
	if !ok {
		return ErrUuidNotExist
	}
	var shareFileInstance SharedFile
	shareFileInstance.SignedShareFileChainUUID = invitationPtr
	shareFileInstance.Sharer = senderUsername

	sharedUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_shared_" + filename))[:16])
	if err != nil {
		return err
	}

	err = StoreData(sharedUUID, userdata.passwordHash, &shareFileInstance)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	_, status, err := userdata.CheckFileStatus(filename)
	if err != nil {
		return err
	}

	if status == FileNotCreated {
		return ErrFileNotFound
	} else if status == SharedPrivilege {
		return ErrPermissionDenied
	}

	storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "_owned_" + filename))[:16])
	if err != nil {
		return err
	}
	var root RootFile
	err = GetData(storageUUID, userdata.passwordHash, &root)
	if err != nil {
		return err
	}
	handler, err := newFileHandler(root.FileID, root.Key)
	if err != nil {
		return err
	}
	newUUID := uuid.New()
	newKey := userlib.RandomBytes(16)
	err = handler.ChangeFileKey(newUUID, newKey)
	if err != nil {
		return err
	}

	root.FileID = newUUID
	root.Key = newKey

	for username, derivedFileUUID := range root.DerivedShareFileUUID {
		if username == recipientUsername+"_"+filename {

			userlib.DatastoreSet(derivedFileUUID, []byte(""))
			userlib.DebugMsg("revoke: " + derivedFileUUID.String())
			continue
		}

		var derivedFile DerivedShareFile
		derivedFile.FileID = root.FileID
		derivedFile.Key = root.Key
		derivedFileEncKey, err := userlib.HashKDF(userdata.passwordHash[:16],
			[]byte(derivedFileUUID.String()))
		if err != nil {
			return err
		}
		userlib.DebugMsg("update uuid: " + derivedFileUUID.String())

		err = StoreData(derivedFileUUID, derivedFileEncKey, &derivedFile)
		if err != nil {
			return err
		}
	}
	err = StoreData(storageUUID, userdata.passwordHash, &root)
	if err != nil {
		return err
	}
	return nil
}
