const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config()
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// jwt middleware
const jwtVerify = (req, res, next) => {
    const authorization = req.headers.authorization;
    // console.log(authorization);
    if (!authorization) {
        return res.status(401).send({ message: 'Unauthorized Access' })
    }
    // bearer token
    const token = authorization.split(' ')[1];

    // verify jwt
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized Access' })
        }
        req.decoded = decoded;
        next();
    })
}



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.z8yqdyj.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();



        const menuCollection = client.db("bistroDb").collection("menu");
        const usersCollection = client.db("bistroDb").collection("users");
        const reviewCollection = client.db("bistroDb").collection("reviews");
        const cartCollection = client.db("bistroDb").collection("carts");



        // jwt(JSON WEB TOKEN)
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
            res.send({ token });
        })

        // middleware of verifyAdmin  //use JwtVerify using verifyAdmin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'forbidden message' });

            }
            next();

        }

        // secure user from hacker
        /**
         * 0) do not show secure link to those who should not see the links
         * 1) use jwtVerify
         * 2) use verifyAdmin middleware
         * 
         * 
         * */
        // user related api that get or show all users
        app.get('/users', jwtVerify, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        })




        // get admin user and security check 1) jwtVerify 2) email 3) check admin
        app.get('/users/admin/:email', jwtVerify, async (req, res) => {
            const email = req.params.email;
            if (req.decoded.email !== email) {
                res.send({ admin: false })
            }
            const query = { email: email }
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' }
            res.send(result);
        })

        // admin update
        app.patch('/users/admin/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    role: 'admin'
                },

            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        })


        // user related api for google account not render many account in data
        app.post('/users', async (req, res) => {
            const user = req.body;

            const query = { email: user.email }
            const existingUser = await usersCollection.findOne(query);

            if (existingUser) {
                return res.send({ message: 'user already exist' })
            }


            const result = await usersCollection.insertOne(user);
            res.send(result);
        })


        // menu related api
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result);
        });
        // menu post or create bu user
        app.post('/menu', jwtVerify, verifyAdmin, async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem)
            res.send(result);
        })
        // menu deleted by admin
        app.delete('/menu/:id', jwtVerify, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await menuCollection.deleteOne(query)
            res.send(result);
        })





        // review related api
        app.get('/reviews', async (req, res) => {
            const result = await reviewCollection.find().toArray();
            res.send(result);
        });


        // cart collection apis
        app.get('/carts', jwtVerify, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                res.send([]);
            }
            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'Unauthorized Access' })
            }
            else {
                const query = { email: email };
                const result = await cartCollection.find(query).toArray()
                res.send(result);
            }

        })


        app.post('/carts', async (req, res) => {
            const item = req.body;
            const result = await cartCollection.insertOne(item);
            res.send(result);
        });

        app.delete('/carts/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(query);
            res.send(result);
        })





        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);






app.get('/', (req, res) => {
    res.send('Boss is ok!')
})

app.listen(port, () => {
    console.log(`Bistro is siting on port: ${port}`);
})


/*****
 * naming convention
 * 
 * user: userCollection
 * app.get('/users')
 * app.get('/users/:id') ---- for get particular user
 * app.post('/users') ---for create user
 * app.patch('/users/:id') ---- for particular user update!
 * app.put('/users/:id') ---- for particular user update!
 * app.delete('/users/:id') ---- for particular user delete!
 * 
 * 
 * 
 * 
 * */ 