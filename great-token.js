var crypto = require('crypto');

var hash = 'md5';
var hmacPassword = undefined;
var cipher = 'aes192;
var cipherPassword = undefined;
var useCipher = false;

var userUsesCipher = undefined;
var expirationTime = 60; // minutes
var tokenFormat = 'hex';



/**********************************************/
/***************** Config *********************/
/**********************************************/


/**************** passwords *******************/

var setPassword = function(password) {

	var usingCipher = useCipher;

	setCipherPassword(password);
	setHashPassword(password);

	useCipher = usingCipher;
};

var setCipherPassword = function(password) {

	if (password.length < 10) {
		console.warning('great-token: Cipher\'s password length too short');
	}

	cipherPassword = password;
	useCipher = true;
};

var setHmacPassword = function(password) {

	if (password.length < 10) {
		console.warning('great-token: Hmac\'s password length too short');
	}

	hmacPassword = password;
	useCipher = false;
};


/******************* algorithms **********************/

var setHash = function(newHash, password) {

	useCipher = false;
	if (newHash in crypto.getHashes()) {
		hash = newHash;
		if (password)
			setHmacPassword(password);
	}
	else {
		console.error('great-token: "'+newHash+'" algorithm not valid for hash. Valid algorithms:', crypto.getHashes());
	}
};

var setCipher = function(newCipher, password) {

	useCipher = true;
	if (newCipher in crypto.getCiphers()) {
		cipher = newCipher;
		if (password)
			setCipherPassword(password);
	}
	else {
		console.error('great-token: "'+newCipher+'" algorithm not valid for cipher. Valid algorithms:', crypto.getCiphers());
	}
};


/********************* others ***********************/

var setUserUsesCipher = function(mustUseCipher) {

	userUsesCipher = mustUseCipher;
};

var setExpirationTime = function(time) {

	expirationTime = time;
};

var setTokenFormat = function(format) {

	validFormats = ['hex', 'base64', 'binary'];
	if (format in validFormats) {
		tokenFormat = format;
	}
	else {
		console.error('great-token: "'+format+'" format not valid for token. Valid formats:', validFormats);
	}
};



/******************************************/
/**************** User ********************/

var User = function(uid, expiration) {

	this.uid = uid;
	this.expirationDate = new Date() + (expiration || expirationTime);

}

var userToData = function(user) {

	return JSON.stringify(user);
};

var dataToUser = function(data) {

	var user;
	
	try {
		user = JSON.parse(data);
	}
	catch (err) {
		user = null;
	}

	if (user &&
		user.uid === undefined ||
		user.expirationDate === undefined)

		user = null;

	return user;
};



/*****************************************************/
/****************** Create token *********************/

var createTokenForUserId = function(uid, expiration) {

	var user = new User(uid, expiration);
	var token;
	if (shouldUseCipher())
		token = encodeUser(user);
	else
		token = digestUser(user);
	return token;
};

var encodeUser = function(user) {

	if (!cipherPassword) {
		console.error('great-token: Cipher\'s password not set');
		return null;
	}

	var encoder = crypto.createCipher(cipher, cipherPassword);
	var data = JSON.stringify(user);

	return encoder.update(data, 'utf-8', tokenFormat) +
		encoder.final(tokenFormat);
};

var digestUser = function(user) {

	var hasher;
	if (hmacPassword)
		hasher = crypto.createHmac(hash, hmacPassword);
	else
		hasher = crypto.createHash(hash);
	var data = userToData(user);

	return hasher.update(data).digest(tokenFormat);
};

var shouldUseCipher = function() {

	var shouldUse;

	if (userUsesCipher !== undefined) {
		shouldUse = userUsesCipher;
	}
	else {
		shouldUse = useCipher;
	}

	return shouldUse;
};



/*************************************************/
/***************** Decode token ******************/

var getUserIdFromToken = function(token) {

	return decodeToken(token);
};

var decodeToken = function(token) {

	if (!cipherPassword) {
		console.error('great-token: Cipher\'s password not set');
		return null;
	}

	var decoder = crypto.createDecipher(cipher, cipherPassword);
	var data = decoder.update(token, tokenFormat, 'utf-8') +
		decoder.final('utf-8');

	return dataToUser(data);
};



/**************************************************/
/********************* API ************************/

exports.setExpirationTime = setExpirationTime;
exports.useCipher = setUserUsesCipher;
exports.setTokenFormat = setTokenFormat;

exports.setPassword = setPassword;
exports.setCipherPassword = setCipherPassword;
exports.setHmacPassword = setHmacPassword;

exports.setCipher = setCipher;
exports.setHash = setHash;

exports.createTokenForUserId = createTokenForUserId;
exports.getUserIdFromToken = getUserIdFromToken;

