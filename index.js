const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const mg = require('nodemailer-mailgun-transport');
require('dotenv').config()
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());



// let transporter = nodemailer.createTransport({
//     host: 'smtp.sendgrid.net',
//     port: 587,
//     auth: {
//         user: "apikey",
//         pass: process.env.SENDGRID_API_KEY
//     }
// })



const auth = {
    auth: {
        api_key: process.env.EMAIL_PRIVATE_KEY,
        domain: process.env.EMAIL_DOMAIN
    }
}

const transporter = nodemailer.createTransport(mg(auth));





// send payment conformation email

const sendPaymentConfirmationEmail = payment => {
    transporter.sendMail({
        from: "abuyeahia24@gmail.com", // verified sender email
        to: "abuyeahia24@gmail.com", // recipient email
        subject: "Your food is confirmed. Enjoy the food soon.", // Subject line
        text: "Hello world!", // plain text body
        html: `
        
        <div>
        <h2>Payment confirm </h2>
        <p>Transaction id: ${payment.transactionId} </p>
        </div>
        
        `, // html body
    }, function (error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });

}










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
        // await client.connect();



        const menuCollection = client.db("bistroDb").collection("menu");
        const usersCollection = client.db("bistroDb").collection("users");
        const reviewCollection = client.db("bistroDb").collection("reviews");
        const cartCollection = client.db("bistroDb").collection("carts");
        const paymentCollection = client.db("bistroDb").collection("payments");



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
                return res.status(403).send({ error: true, message: 'forbidden Access' })
            }
            else {
                const query = { email: email };
                const result = await cartCollection.find(query).toArray()
                res.send(result);
            }

        })

        // carts section create and delete
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



        // create payment intent
        app.post('/create-payment-intent', async (req, res) => {
            const { price } = req.body;
            const amount = parseInt(price * 100);
            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            });
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })


        // payment related api
        app.post('/payments', jwtVerify, async (req, res) => {
            const payment = req.body;
            const insertedResult = await paymentCollection.insertOne(payment)


            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
            const deleteResult = await cartCollection.deleteMany(query)

            // send an email confirming email
            sendPaymentConfirmationEmail(payment);


            res.send({ insertedResult, deleteResult });
        })

        // admin stats
        app.get('/admin-stats', jwtVerify, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            // best to get sum of the price field  is to use group and sum operators


            /* 
            
         await paymentCollection.aggregate([
                {
                    $group: {
                        _id: null,
                        total: {$sum: '$price}
                    }
                }
            ]).toArray()
            
            
            */


            const payments = await paymentCollection.find().toArray();
            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0)


            res.send({
                users,
                products,
                orders,
                revenue
            })
        })

        /***
         * -----------------
         * 
         * 
         * 2) BANGLA  system(second best solution)
         * 
         * --------
         * 
         * 1) load all payments
         * 2) for each payment, get the menuItems array
         * 3)foe each item in the menuItem array get the menuItem from
         * the menu
         * 4) put them in an array: allOrderedItems
         * 5) separate allOrderedItems by category using filter
         * 6)now get the quantity by using length: pizzas.length
         * 7)for each category use reduce to get the
         * total amount spent on this category
         * 
         * 
         * 
         * 
         * 
         * 
         * *
         * 
         * 
         */


        // admin order stats with chart
        app.get('/order-stats', jwtVerify, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $lookup: {
                        from: 'menu',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemsData'
                    }
                },
                {
                    $unwind: '$menuItemsData'
                },
                {
                    $group: {
                        _id: '$menuItemsData.category',
                        count: { $sum: 1 },
                        total: { $sum: '$menuItemsData.price' }
                    }
                },
                {
                    $project: {
                        category: '$_id',
                        count: 1,
                        total: { $round: ['$total', 2] }
                    }
                }
            ];

            const result = await paymentCollection.aggregate(pipeline).toArray()
            res.send(result)

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