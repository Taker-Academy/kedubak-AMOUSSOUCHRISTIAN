const express = require('express');
const server = express();
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const PORT = process.env.PORT || 8080;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URL || !JWT_SECRET) {
    console.error('Missing necessary environment variables');
    process.exit(1);
}

// Connexion à MongoDB
function Connect_to_database() {
    mongoose.connect(MONGO_URL);
    const db = mongoose.connection;
    db.on('error', console.error.bind(console, 'Erreur de connexion à MongoDB :'));
    db.once('open', () => {
        console.log('Connecté à MongoDB');
    });
}

Connect_to_database();

// Schéma et modèle d'utilisateur
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true }
}, { collection: 'users' });

const User = mongoose.model('create_user', userSchema);

// gestion de la route /auth/register
async function registerUser(req, res) {
    console.log(req.body);
    const { email, password, firstName, lastName } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Un utilisateur avec cette adresse e-mail existe déjà' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            email,
            password: hashedPassword,
            firstName,
            lastName
        });
        await newUser.save();
        const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '24h' });
        console.log("Token", token);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Authorization', 'Bearer ' + token);
        res.status(201).json({
            ok: true,
            data: {
                token,
                user: {
                    email: newUser.email,
                    firstName: newUser.firstName,
                    lastName: newUser.lastName
                }
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, message: 'Erreur lors de la création de l\'utilisateur' });
    }
}

// gestion de la route /auth/login
async function loginUser(req, res) {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Adresse e-mail ou mot de passe incorrect' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Adresse e-mail ou mot de passe incorrect' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Authorization', 'Bearer ' + token);
        res.status(200).json({
            ok: true,
            data: {
                token,
                user: {
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName
                }
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erreur lors de la tentative de connexion' });
    }
}

function ensureToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    } else {
        res.sendStatus(403);
    }
}

server.post('/auth/register', registerUser);
server.post('/auth/login', loginUser);

  // pour vérifier le token JWT
async function verifyToken(req, res) {
    try {
        const decoded = jwt.verify(req.token, 'JWT_SECRET');
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(500).json({ message: 'Utilisateur introuvable' });
        }
        return user;
    } catch (error) {
        console.error(error);
        return res.status(401).json({ message: 'Mauvais token JWT' });
    }
}

// obtenir les infos du user
server.get('/user/me', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        res.status(200).json({
            ok: true,
            data: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    }
});

// mettre à jour les infos du user
server.put('/user/edit', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        if (req.body.firstName) {
            user.firstName = req.body.firstName;
        }
        if (req.body.lastName) {
            user.lastName = req.body.lastName;
        }
        if (req.body.email) {
            user.email = req.body.email;
        }
        if (req.body.password) {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            user.password = hashedPassword;
        }
        await user.save();
        res.status(200).json({
            ok: true,
            data: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    }
});

// supprimer un utilisateur
server.delete('/user/remove', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        await User.findByIdAndDelete(user._id);
        res.status(200).json({
            ok: true,
            data: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                removed: true
            }
        });
    }
});

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    content: String,
    createdAt: { type: Date, default: Date.now },
    comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    upVotes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  }, {collection: 'posts'});

  const Post = mongoose.model('Post', postSchema);

// obtenir tous posts
server.get('/post', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const posts = await Post.find({});
        res.status(200).json({
            ok: true,
            data: posts
        });
    }
});

// créer un nouveau post
server.post('/post', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const { title, content } = req.body;
        const newPost = new Post({
            userId: user._id,
            title: title,
            content: content,
            createdAt: new Date(),
            comments: [],
            upVotes: []
        });

        await newPost.save();

        res.status(201).json({
            ok: true,
            data: {
                _id: newPost._id,
                createdAt: newPost.createdAt,
                userId: user._id,
                firstName: user.firstName,
                title: newPost.title,
                content: newPost.content,
                comments: newPost.comments,
                upVotes: newPost.upVotes
            }
        });
    }
});

// obtenir les posts user
server.get('/post/me', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const posts = await Post.find({ userId: user._id });
        res.status(200).json({
            ok: true,
            data: posts
        });
    }
});

// obtenir un post par ID
server.get('/post/:id', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const postId = req.params.id;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post non trouvé' });
        }
        res.status(200).json({
            ok: true,
            data: post
        });
    }
});

// supprimer un post par ID
server.delete('/post/:id', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const postId = req.params.id;
        const post = await Post.findOneAndDelete({ _id: postId, userId: user._id });
        if (!post) {
            return res.status(404).json({ message: 'Post non trouvé' });
        }
        res.status(200).json({
            ok: true,
            data: {
                message: 'Post supprimé avec succès'
            }
        });
    }
});

// voter pour un post
server.post('/post/vote/:id', ensureToken, async (req, res) => {
    const user = await verifyToken(req, res);
    if (user && user._id) {
        const postId = req.params.id;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post non trouvé' });
        }
        const alreadyUpvoted = post.upVotes.includes(user._id);
        if (alreadyUpvoted) {
            return res.status(409).json({ message: 'Vous avez déjà voté pour ce post.' });
        }
        post.upVotes.push(user._id);
        await post.save();
        res.status(200).json({
            ok: true,
            message: "Post voté avec succès"
        });
    }
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});