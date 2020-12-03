const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');
//const { check, validationResult } = require('express-validator/check');

const { check, validationResult } = require('express-validator');

const User = require('../../modules/User'); //Bring in our user model
const { getMaxListeners } = require('../../modules/User');

//@route    POST api/users
//@desc     Register user
//@access   Public
router.post(
	'/',
	[
		check('name', 'Name is required').not().isEmpty(),
		check('email', 'Please include a valid email').isEmail(),
		check(
			'password',
			'Please enter a password with 6 or more characters'
		).isLength({ min: 6 }),
	],
	async (req, res) => {
		const errors = validationResult(req);

		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			//See if user exist
			let user = await User.findOne({ email });

			if (user) {
				return res
					.status(400)
					.json({ errors: [{ msg: 'User already exist' }] });
			}

			//Get users Gravatar
			const avatar = gravatar.url(email, {
				s: '200', //Default size
				r: 'pg', //Rating
				d: 'mm', //Default
			});

			user = new User({
				name,
				email,
				avatar,
				password,
			});

			//Encrypt the password
			const salt = await bcrypt.genSalt(10); // .genSalt(rounds)

			user.password = await bcrypt.hash(password, salt); //Takes plain text password, then the salt creating a hash

			await user.save();

			//Return the JSON web token
			const payload = {
				user: {
					id: user.id, //with mongoose is not needed to use '_id' due to an abstraction
				},
			};

			return res.json({ payload });
			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{ expiresIn: 360000 }, //In seconds
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server error');
		}
	}
);

module.exports = router;
