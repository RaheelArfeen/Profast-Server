const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Added for JWT
const cookieParser = require('cookie-parser'); // Added for JWT
const dotenv = require('dotenv');
dotenv.config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");
const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);

const app = express();
const port = 3000;

// Middlewares
app.use(cors({
    origin: ["http://localhost:5173"],
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser()); // Use cookie-parser for JWT

// --- Firebase Admin SDK Initialization ---
let serviceAccount;
try {
    if (process.env.FB_SERVICE_KEY && process.env.FB_SERVICE_KEY.endsWith(".json")) {
        // Attempt to load from a file path
        serviceAccount = require(`./${process.env.FB_SERVICE_KEY}`);
        console.log("Firebase initialized using JSON file path.");
    } else if (process.env.FB_SERVICE_KEY) {
        // Assume base64 string if not a file path
        const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
        serviceAccount = JSON.parse(decodedKey);
        console.log("Firebase initialized using base64 string.");
    } else {
        console.error("FB_SERVICE_KEY environment variable is not set.");
        process.exit(1); // Exit if Firebase key is critical and missing
    }

    if (serviceAccount) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
        });
    }
} catch (error) {
    console.error("Error initializing Firebase Admin SDK:", error);
    process.exit(1); // Exit if Firebase initialization fails
}


// --- MongoDB Connection ---
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.hqacvhm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server (optional starting in v4.7)
        // await client.connect(); // Uncomment if you want to explicitly connect at startup

        const db = client.db("servicedb");
        const usersCollection = db.collection("users");
        const parcelsCollection = db.collection("parcels");
        const paymentsCollection = db.collection("payments");
        const ridersCollection = db.collection("riders");
        const trackingsCollection = db.collection("trackings"); // Renamed for consistency

        // --- Custom Middlewares ---

        // Middleware for Firebase ID Token verification
        const verifyFBToken = async (req, res, next) => {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).send({ message: 'Unauthorized access: No token provided or malformed header' });
            }
            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).send({ message: 'Unauthorized access: Token is missing' });
            }

            try {
                const decoded = await admin.auth().verifyIdToken(token);
                req.decoded = decoded; // Attach decoded token to request
                next();
            } catch (error) {
                console.error("Firebase token verification error:", error);
                return res.status(403).send({ message: 'Forbidden access: Invalid or expired token' });
            }
        };

        // Middleware for JWT verification (for cookie-based authentication)
        const verifyToken = (req, res, next) => {
            const token = req.cookies?.token;
            if (!token) {
                return res.status(401).send({ message: "Unauthorized access: No JWT token found" });
            }

            jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, decoded) => {
                if (err) {
                    console.error("JWT verification error:", err);
                    return res.status(401).send({ message: "Unauthorized access: Invalid JWT token" });
                }
                req.decoded = decoded; // Attach decoded token to request
                next();
            });
        };

        // Middleware to verify if the user is an admin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded?.email; // Decoded from either FB or JWT token
            if (!email) {
                return res.status(401).send({ message: 'Unauthorized access: Email not found in token' });
            }
            const query = { email };
            const user = await usersCollection.findOne(query);
            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'Forbidden access: Not an admin' });
            }
            next();
        };

        // Middleware to verify if the user is a rider
        const verifyRider = async (req, res, next) => {
            const email = req.decoded?.email; // Decoded from either FB or JWT token
            if (!email) {
                return res.status(401).send({ message: 'Unauthorized access: Email not found in token' });
            }
            const query = { email };
            const user = await usersCollection.findOne(query);
            if (!user || user.role !== 'rider') {
                return res.status(403).send({ message: 'Forbidden access: Not a rider' });
            }
            next();
        };

        // --- AUTH ROUTES ---

        // Login route for JWT cookie-based authentication
        app.post("/login", async (req, res) => {
            const { email } = req.body;
            if (!email) return res.status(400).send({ message: "Email is required" });

            try {
                const user = await usersCollection.findOne({ email });
                if (!user) return res.status(401).send({ message: "Invalid email" });

                const payload = { email: user.email, id: user._id.toString() };
                const token = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: "1h" });

                res.cookie("token", token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 'none' for cross-site cookies in production
                    maxAge: 3600000, // 1 hour
                });

                res.send({ message: "Login successful", user: { email: user.email, role: user.role } });
            } catch (error) {
                console.error("Login error:", error);
                res.status(500).send({ message: "Internal server error during login" });
            }
        });

        // Logout route to clear JWT cookie
        app.post("/logout", (req, res) => {
            res.clearCookie("token", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 'none' for cross-site cookies in production
            });
            res.send({ message: "Logged out successfully" });
        });

        // --- USER ROUTES ---

        // GET: All users or a specific user by email (query parameter)
        // This route does not require authentication to allow public checks for user existence
        app.get("/users", async (req, res) => {
            const { email } = req.query;
            try {
                if (email) {
                    const user = await usersCollection.findOne({ email });
                    return res.send(user ? [user] : []);
                } else {
                    const users = await usersCollection.find().toArray();
                    return res.send(users);
                }
            } catch (error) {
                console.error("Error fetching users:", error);
                res.status(500).send({ error: "Failed to fetch users" });
            }
        });

        // GET: A specific user by email (route parameter)
        app.get("/users/:email", async (req, res) => {
            try {
                const user = await usersCollection.findOne({ email: req.params.email });
                if (!user) return res.status(404).send({ message: "User not found" });
                res.send(user);
            } catch (error) {
                console.error("Error fetching user by email:", error);
                res.status(500).send({ error: "Failed to fetch user" });
            }
        });

        // POST: Create or update a user (upsert)
        // This is typically used when a user first signs up with Firebase.
        app.post("/users", async (req, res) => {
            const { email, displayName, photoURL, lastSignInTime, role = 'user' } = req.body; // Default role to 'user'
            if (!email) return res.status(400).send({ error: "Email is required" });

            try {
                const result = await usersCollection.updateOne(
                    { email },
                    {
                        $set: {
                            displayName,
                            photoURL,
                            lastSignInTime,
                            role // Role can be updated or set on first creation
                        }
                    },
                    { upsert: true } // Create if not exists, update if exists
                );
                res.status(201).send(result);
            } catch (error) {
                console.error("Error upserting user:", error);
                res.status(500).send({ error: "Failed to upsert user" });
            }
        });

        // GET: Get user role by email
        app.get("/users/role/:email", async (req, res) => {
            try {
                const user = await usersCollection.findOne({ email: req.params.email });
                if (!user) return res.status(404).json({ message: "User not found" });
                res.json({ role: user.role || "user" }); // Default to 'user' if role is not set
            } catch (error) {
                console.error("Error fetching user role:", error);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        // PATCH: Promote user to admin (using JWT for admin check)
        // This route demonstrates how to use the JWT `verifyToken` middleware.
        app.patch("/users/make-admin/:email", verifyToken, async (req, res) => {
            const targetEmail = req.params.email;
            const requesterEmail = req.decoded?.email;

            try {
                const requester = await usersCollection.findOne({ email: requesterEmail });
                if (requester?.role !== "admin") {
                    return res.status(403).send({ message: "Forbidden: Only admins can promote users" });
                }

                const result = await usersCollection.updateOne(
                    { email: targetEmail },
                    { $set: { role: "admin" } }
                );

                res.send({ message: "User promoted to admin", result });
            } catch (error) {
                console.error("Error promoting user to admin:", error);
                res.status(500).send({ message: "Internal server error" });
            }
        });

        // PATCH: Update user role by ID (using Firebase Token for admin check)
        // This route demonstrates how to use the Firebase `verifyFBToken` middleware.
        app.patch("/users/:id/role", verifyFBToken, verifyAdmin, async (req, res) => {
            const { id } = req.params;
            const { role } = req.body;

            if (!["admin", "user", "rider"].includes(role)) { // Include 'rider' as a valid role
                return res.status(400).send({ message: "Invalid role" });
            }

            try {
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role } }
                );
                if (result.modifiedCount === 0) {
                    return res.status(404).send({ message: "User not found or role already set" });
                }
                res.send({ message: `User role updated to ${role}`, result });
            } catch (error) {
                console.error("Error updating user role:", error);
                res.status(500).send({ message: "Failed to update user role" });
            }
        });

        // --- PARCEL ROUTES ---

        // GET: All parcels OR parcels by user (created_by), sorted by latest
        app.get("/parcels", async (req, res) => {
            try {
                const { email, payment_status, delivery_status } = req.query;
                let query = {};
                if (email) query.created_by = email;
                if (payment_status) query.payment_status = payment_status;
                if (delivery_status) query.delivery_status = delivery_status;

                const parcels = await parcelsCollection.find(query).sort({ createdAt: -1 }).toArray();
                res.send(parcels);
            } catch (error) {
                console.error("Error fetching parcels:", error);
                res.status(500).send({ message: "Failed to get parcels" });
            }
        });

        // GET: Get a specific parcel by ID
        app.get('/parcels/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });

                if (!parcel) {
                    return res.status(404).send({ message: 'Parcel not found' });
                }
                res.send(parcel);
            } catch (error) {
                console.error('Error fetching parcel:', error);
                res.status(500).send({ message: 'Failed to fetch parcel' });
            }
        });

        // GET: Get delivery status counts for parcels (for dashboards)
        app.get('/parcels/delivery/status-count', async (req, res) => {
            const pipeline = [
                {
                    $group: {
                        _id: '$delivery_status',
                        count: { $sum: 1 }
                    }
                },
                {
                    $project: {
                        status: '$_id',
                        count: 1,
                        _id: 0
                    }
                }
            ];

            try {
                const result = await parcelsCollection.aggregate(pipeline).toArray();
                res.send(result);
            } catch (error) {
                console.error('Error aggregating parcel status:', error);
                res.status(500).send({ message: 'Failed to get delivery status counts' });
            }
        });

        app.get('/rider/parcels/me', async (req, res) => {
            try {
                const parcels = await parcelsCollection.find({}).toArray();
                res.send(parcels);
            } catch (error) {
                console.error('Error fetching parcels:', error);
                res.status(500).send({ message: 'Failed to get parcels' });
            }
        });

        // GET: Get pending delivery tasks for a rider
        app.get('/rider/parcels', verifyFBToken, verifyRider, async (req, res) => {
            try {
                const email = req.query.email;
                if (!email) {
                    return res.status(400).send({ message: 'Rider email is required' });
                }
                // Ensure the rider is only fetching their own assigned parcels
                if (req.decoded.email !== email) {
                    return res.status(403).send({ message: 'Forbidden access' });
                }

                const query = {
                    assigned_rider_email: email,
                    delivery_status: { $in: ['rider_assigned', 'in_transit'] },
                };
                const options = {
                    sort: { creation_date: -1 }, // Newest first
                };

                const parcels = await parcelsCollection.find(query, options).toArray();
                res.send(parcels);
            } catch (error) {
                console.error('Error fetching rider tasks:', error);
                res.status(500).send({ message: 'Failed to get rider tasks' });
            }
        });

        // GET: Load completed parcel deliveries for a rider
        app.get('/rider/completed-parcels', verifyFBToken, verifyRider, async (req, res) => {
            try {
                const email = req.query.email;
                if (!email) {
                    return res.status(400).send({ message: 'Rider email is required' });
                }
                // Ensure the rider is only fetching their own completed parcels
                if (req.decoded.email !== email) {
                    return res.status(403).send({ message: 'Forbidden access' });
                }

                const query = {
                    assigned_rider_email: email,
                    delivery_status: {
                        $in: ['delivered', 'service_center_delivered']
                    },
                };
                const options = {
                    sort: { creation_date: -1 }, // Latest first
                };

                const completedParcels = await parcelsCollection.find(query, options).toArray();
                res.send(completedParcels);

            } catch (error) {
                console.error('Error loading completed parcels:', error);
                res.status(500).send({ message: 'Failed to load completed deliveries' });
            }
        });

        // POST: Create a new parcel
        app.post('/parcels', async (req, res) => {
            try {
                const newParcel = req.body;
                newParcel.createdAt = new Date(); // Add creation timestamp
                newParcel.delivery_status = 'pending'; // Initial status
                newParcel.payment_status = 'unpaid'; // Initial payment status
                const result = await parcelsCollection.insertOne(newParcel);
                res.status(201).send(result);
            } catch (error) {
                console.error('Error inserting parcel:', error);
                res.status(500).send({ message: 'Failed to create parcel' });
            }
        });

        // PATCH: Assign a rider to a parcel
        app.patch("/parcels/:id/assign", verifyFBToken, verifyAdmin, async (req, res) => { // Added admin verification
            const parcelId = req.params.id;
            const { riderId, riderName, riderEmail } = req.body;

            try {
                // Update parcel
                const parcelUpdateResult = await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    {
                        $set: {
                            delivery_status: "rider_assigned",
                            assigned_rider_id: riderId,
                            assigned_rider_email: riderEmail,
                            assigned_rider_name: riderName,
                            assigned_at: new Date(), // Add assignment timestamp
                        },
                    }
                );

                if (parcelUpdateResult.modifiedCount === 0) {
                    return res.status(404).send({ message: "Parcel not found or already assigned" });
                }

                // Update rider status (optional, depends on your logic for rider availability)
                await ridersCollection.updateOne(
                    { _id: new ObjectId(riderId) },
                    {
                        $set: {
                            // work_status: "in_delivery", // You might want to update this when they pick up
                        },
                    }
                );

                res.send({ message: "Rider assigned successfully" });
            } catch (err) {
                console.error("Error assigning rider:", err);
                res.status(500).send({ message: "Failed to assign rider" });
            }
        });

        // PATCH: Update parcel delivery status
        app.patch("/parcels/:id/status", verifyFBToken, async (req, res) => { // Added FB token verification
            const parcelId = req.params.id;
            const { status } = req.body;
            const updatedDoc = {
                delivery_status: status
            };

            // Add specific timestamps based on status
            if (status === 'in_transit') {
                updatedDoc.picked_at = new Date().toISOString();
            } else if (status === 'delivered') {
                updatedDoc.delivered_at = new Date().toISOString();
            }

            try {
                const result = await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    { $set: updatedDoc }
                );
                if (result.modifiedCount === 0) {
                    return res.status(404).send({ message: "Parcel not found or status already set" });
                }
                res.send(result);
            } catch (error) {
                console.error("Error updating parcel status:", error);
                res.status(500).send({ message: "Failed to update status" });
            }
        });

        // PATCH: Rider cashout for their delivered parcel
        app.patch("/parcels/:id/cashout", verifyFBToken, verifyRider, async (req, res) => {
            const parcelId = req.params.id;
            const riderEmail = req.decoded.email;

            try {
                // 1. Find the parcel
                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(parcelId) });

                if (!parcel) {
                    return res.status(404).send({ message: "Parcel not found" });
                }

                // 2. Ensure rider is the assigned rider
                if (parcel.assigned_rider_email !== riderEmail) {
                    return res.status(403).send({ message: "Forbidden: This parcel is not assigned to you" });
                }

                // 3. Check if already cashed out
                if (parcel.cashout_status === "cashed_out") {
                    return res.status(400).send({ message: "This parcel has already been cashed out" });
                }

                // 4. Check if delivery is completed
                if (!["delivered", "service_center_delivered"].includes(parcel.delivery_status)) {
                    return res.status(400).send({ message: "Parcel must be delivered before cashout" });
                }

                // 5. Perform cashout
                const result = await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    {
                        $set: {
                            cashout_status: "cashed_out",
                            cashed_out_at: new Date()
                        }
                    }
                );

                if (result.modifiedCount === 0) {
                    return res.status(500).send({ message: "Failed to update parcel cashout status" });
                }

                res.send({ message: "Cashout successful", result });

            } catch (error) {
                console.error("Error during cashout:", error);
                res.status(500).send({ message: "Internal server error during cashout" });
            }
        });

        // DELETE: Delete a parcel
        app.delete('/parcels/:id', verifyFBToken, verifyAdmin, async (req, res) => { // Added admin verification
            try {
                const id = req.params.id;
                const result = await parcelsCollection.deleteOne({ _id: new ObjectId(id) });
                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: 'Parcel not found' });
                }
                res.send(result);
            } catch (error) {
                console.error('Error deleting parcel:', error);
                res.status(500).send({ message: 'Failed to delete parcel' });
            }
        });

        // --- TRACKING ROUTES ---

        // GET: Get all tracking updates for a given tracking ID
        app.get("/trackings/:trackingId", async (req, res) => {
            const trackingId = req.params.trackingId;
            try {
                const updates = await trackingsCollection
                    .find({ tracking_id: trackingId })
                    .sort({ timestamp: 1 }) // Sort by time ascending
                    .toArray();
                res.json(updates);
            } catch (error) {
                console.error("Error fetching tracking updates:", error);
                res.status(500).send({ message: "Failed to retrieve tracking information" });
            }
        });

        // POST: Add a new tracking update
        app.post("/trackings", async (req, res) => {
            const update = req.body;
            update.timestamp = new Date(); // Ensure correct timestamp
            if (!update.tracking_id || !update.status) {
                return res.status(400).json({ message: "tracking_id and status are required." });
            }

            try {
                const result = await trackingsCollection.insertOne(update);
                res.status(201).json(result);
            } catch (error) {
                console.error("Error inserting tracking update:", error);
                res.status(500).json({ message: "Failed to add tracking update." });
            }
        });

        // --- RIDER ROUTES ---

        app.get("/riders", async (req, res) => {
            try {
                const riders = await ridersCollection.find({}).toArray();
                res.send(riders);
            } catch (error) {
                res.status(500).send({ message: "Failed to load riders" });
            }
        });

        // POST: Register a new rider
        app.post('/riders', async (req, res) => {
            const rider = req.body;
            // You might want to set an initial status like 'pending' here
            rider.status = 'pending'; // Default status for new riders
            try {
                const result = await ridersCollection.insertOne(rider);
                res.status(201).send(result);
            } catch (error) {
                console.error("Error creating rider:", error);
                res.status(500).send({ message: "Failed to register rider" });
            }
        });

        // GET: Get pending rider applications (admin only)
        app.get("/riders/pending", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const pendingRiders = await ridersCollection
                    .find({ status: "pending" })
                    .toArray();
                res.send(pendingRiders);
            } catch (error) {
                console.error("Failed to load pending riders:", error);
                res.status(500).send({ message: "Failed to load pending riders" });
            }
        });

        // GET: Get active riders (admin only)
        app.get("/riders/active", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const result = await ridersCollection.find({ status: "active" }).toArray();
                res.send(result);
            } catch (error) {
                console.error("Error fetching active riders:", error);
                res.status(500).send({ message: "Failed to load active riders" });
            }
        });

        // GET: Get available riders by district
        app.get("/riders/available", async (req, res) => {
            const { district } = req.query;
            try {
                const riders = await ridersCollection.find({ district }).toArray();
                res.send(riders);
            } catch (err) {
                res.status(500).send({ message: "Failed to load riders" });
            }
        });

        // PATCH: Update rider status (admin only)
        app.patch("/riders/:id/status", verifyFBToken, verifyAdmin, async (req, res) => {
            const { id } = req.params;
            const { status, email } = req.body;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    status
                }
            };

            try {
                const result = await ridersCollection.updateOne(query, updateDoc);
                if (result.modifiedCount === 0) {
                    return res.status(404).send({ message: "Rider not found or status already set" });
                }

                // Update user role to 'rider' in usersCollection if status becomes 'active'
                if (status === 'active') {
                    const userQuery = { email };
                    const userUpdateDoc = {
                        $set: {
                            role: 'rider'
                        }
                    };
                    const roleResult = await usersCollection.updateOne(userQuery, userUpdateDoc);
                    console.log(`User role updated to 'rider' for ${email}: ${roleResult.modifiedCount} modified`);
                }
                res.send(result);
            } catch (err) {
                console.error("Error updating rider status:", err);
                res.status(500).send({ message: "Failed to update rider status" });
            }
        });

        // --- PAYMENT ROUTES ---

        // GET: Get payment history for a user
        app.get('/payments', verifyFBToken, async (req, res) => {
            try {
                const userEmail = req.query.email;
                if (!userEmail) {
                    return res.status(400).send({ message: 'Email query parameter is required.' });
                }
                // Ensure user is only fetching their own payment history
                if (req.decoded.email !== userEmail) {
                    return res.status(403).send({ message: 'Forbidden access' });
                }

                const query = { email: userEmail };
                const options = { sort: { paid_at: -1 } }; // Latest first

                const payments = await paymentsCollection.find(query, options).toArray();
                res.send(payments);
            } catch (error) {
                console.error('Error fetching payment history:', error);
                res.status(500).send({ message: 'Failed to get payments' });
            }
        });

        // POST: Record payment and update parcel status
        app.post('/payments', async (req, res) => {
            try {
                const { parcelId, email, amount, paymentMethod, transactionId } = req.body;

                // 1. Update parcel's payment_status
                const updateResult = await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    {
                        $set: {
                            payment_status: 'paid'
                        }
                    }
                );

                if (updateResult.modifiedCount === 0) {
                    return res.status(404).send({ message: 'Parcel not found or already paid' });
                }

                // 2. Insert payment record
                const paymentDoc = {
                    parcelId,
                    email,
                    amount,
                    paymentMethod,
                    transactionId,
                    paid_at_string: new Date().toISOString(),
                    paid_at: new Date(),
                };

                const paymentResult = await paymentsCollection.insertOne(paymentDoc);

                res.status(201).send({
                    message: 'Payment recorded and parcel marked as paid',
                    insertedId: paymentResult.insertedId,
                });

            } catch (error) {
                console.error('Payment processing failed:', error);
                res.status(500).send({ message: 'Failed to record payment' });
            }
        });

        // Stripe: Create Payment Intent
        app.post('/create-payment-intent', async (req, res) => {
            const { amountInCents } = req.body;
            if (!amountInCents || amountInCents <= 0) {
                return res.status(400).json({ error: "Amount in cents is required and must be positive." });
            }
            try {
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amountInCents, // Amount in cents
                    currency: 'usd',
                    payment_method_types: ['card'],
                });
                res.json({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                console.error("Error creating payment intent:", error);
                res.status(500).json({ error: error.message });
            }
        });


        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close(); // Only close if you want to explicitly disconnect
    }
}
run().catch(console.dir);


// Sample root route
app.get('/', (req, res) => {
    res.send('Parcel Delivery Server is running');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});
