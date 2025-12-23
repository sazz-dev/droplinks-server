require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");

const port = process.env.PORT || 3000;
const host = "0.0.0.0";

// ---------- Firebase Admin ----------
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// ---------- Middleware ---------- //
app.use(
  cors({
    origin: [
      process.env.CLIENT_DOMAIN,
      "http://localhost:5173",
      "https://droplinks.org",
      "http://192.168.0.102:5173",
    ],
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// ---------- JWT Middleware ----------
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (error) {
    return res.status(401).send({ message: "Invalid Token" });
  }
};

// ---------- MongoDB ----------
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  const db = client.db("droplinksDB");
  const usersCollection = db.collection("users");
  const donationRequests = db.collection("donationRequests");
  const fundsCollection = db.collection("funds");

  // ---------- Role Middlewares ----------
  const verifyAdmin = async (req, res, next) => {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    if (user?.role !== "admin")
      return res.status(403).send({ message: "Admin only" });
    next();
  };

  // ---------- Blocked User Middleware ----------
  const verifyActiveUser = async (req, res, next) => {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.status === "blocked") {
      return res.status(403).send({
        message: "Your account has been blocked. Contact admin.",
      });
    }
    next();
  };

  // ---------- Create User ----------
  app.post("/user", async (req, res) => {
    const userData = {
      ...req.body,
      role: "donor",
      status: "active",
      created_at: new Date().toISOString(),
      last_loggedIn: new Date().toISOString(),
    };

    const existing = await usersCollection.findOne({ email: userData.email });

    if (existing) {
      await usersCollection.updateOne(
        { email: userData.email },
        { $set: { last_loggedIn: new Date().toISOString() } }
      );
      return res.send({ message: "User updated" });
    }

    const result = await usersCollection.insertOne(userData);
    res.send(result);
  });

  // ---------- Get All Users (Admin) ----------

  app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
    const adminEmail = req.tokenEmail;
    const users = await usersCollection
      .find({ email: { $ne: adminEmail } }) 
      .toArray();
    res.send(users);
  });

  // ---------- Update Role / Status -------------
  app.patch("/update-role", verifyJWT, verifyAdmin, async (req, res) => {
    const { email, role, status } = req.body;

    if (email === req.tokenEmail && status === "blocked") {
      return res.status(400).send({ message: "Admin cannot block himself" });
    }

    const result = await usersCollection.updateOne(
      { email },
      { $set: { role, status } }
    );
    res.send(result);
  });

  // ---------- Get The User Data ----------
  app.get("/users/:email", verifyJWT, async (req, res) => {
    if (req.params.email !== req.tokenEmail) {
      return res.status(403).send({ message: "Forbidden" });
    }

    const user = await usersCollection.findOne({
      email: req.tokenEmail,
    });

    res.send(user);
  });

  // ---------- Update User Profile ----------
  app.patch("/users", verifyJWT, async (req, res) => {
    const { name, district, upazila, bloodGroup } = req.body;

    const result = await usersCollection.updateOne(
      { email: req.tokenEmail },
      {
        $set: {
          name,
          district,
          upazila,
          bloodGroup,
        },
      }
    );

    res.send(result);
  });

  // ---------- Get User Role ----------
  app.get("/user/role", verifyJWT, async (req, res) => {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    res.send({ role: user?.role, status: user?.status });
  });

  // ---------- Get the Donors ----------
  app.get("/donors", async (req, res) => {
    try {
      const donors = await usersCollection
        .find({ role: "donor" })
        .toArray();

      res.send(donors);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Failed to fetch donors" });
    }
  });

  // ---------- Create Donation Request ----------
  app.post(
    "/donation-requests",
    verifyJWT,
    verifyActiveUser,
    async (req, res) => {
      const result = await donationRequests.insertOne(req.body);
      res.send(result);
    }
  );

  // ---------- Get All Donation Requests ----------
  app.get("/donation-requests", verifyJWT, async (req, res) => {
    const result = await donationRequests.find().toArray();
    res.send(result);
  });

  // ---------- Get Pending Donation Requests ----------
  app.get("/donation-requests/pending", async (req, res) => {
    const result = await donationRequests.find({ status: "Pending" }).toArray();
    res.send(result);
  });
  // Details get
  app.get("/donation-requests/:id", verifyJWT, async (req, res) => {
    const id = req.params.id;
    const ObjectId = require("mongodb").ObjectId;

    try {
      const result = await donationRequests.findOne({ _id: new ObjectId(id) });
      if (!result) {
        return res.status(404).send({ message: "Donation request not found" });
      }
      res.send(result);
    } catch (error) {
      res.status(400).send({ message: "Invalid ID format" });
    }
  });

  // ---------- Edit Donation Request ----------
  app.patch(
    "/donation-requests/:id",
    verifyJWT,
    verifyActiveUser,
    async (req, res) => {
      delete req.body._id;
      const result = await donationRequests.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: req.body }
      );
      res.send(result);
    }
  );

  // ---------- Update Donation Status ----------
  app.patch(
    "/donation-requests",
    verifyJWT,
    verifyActiveUser,
    async (req, res) => {
      const { id, status } = req.body;
      const result = await donationRequests.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );
      res.send(result);
    }
  );

  // ---------- Delete Donation Request ----------
  app.delete(
    "/donation-requests/:id",
    verifyJWT,
    verifyActiveUser,
    async (req, res) => {
      const result = await donationRequests.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    }
  );

  // ---------- My Donation Requests ----------
app.get("/my-donation-requests", verifyJWT, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  const filter = { requesterEmail: req.tokenEmail };

  const total = await donationRequests.countDocuments(filter);
  const data = await donationRequests
    .find(filter)
    .skip(skip)
    .limit(limit)
    .sort({ donationDate: -1 })
    .toArray();

  res.send({
    data,
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  });
});

  // ---------- Stripe Checkout ----------
  app.post("/create-checkout-session", verifyJWT, async (req, res) => {
    const { email, name, image, amount } = req.body;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: email,
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: amount * 100,
            product_data: { name: "Fund Deposit" },
          },
          quantity: 1,
        },
      ],
      metadata: { name, image },
      success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/funding`,
    });

    res.send({ url: session.url });
  });

  // ---------- Payment Success ----------
  app.post("/payment-success", async (req, res) => {
    const session = await stripe.checkout.sessions.retrieve(req.body.sessionId);

    const exists = await fundsCollection.findOne({
      transactionId: session.payment_intent,
    });

    if (!exists) {
      await fundsCollection.insertOne({
        transactionId: session.payment_intent,
        payerEmail: session.customer_details.email,
        payerName: session.metadata?.name || "Anonymous",
        payerImage: session.metadata?.image || "",
        amountTotal: session.amount_total / 100,
        paymentDate: new Date().toISOString(),
      });
    }

    res.send({ success: true });
  });

  // ---------- Get Funds ----------
  app.get("/funds", async (req, res) => {
    const funds = await fundsCollection.find().toArray();
    res.send(funds);
  });

  // ---------- Admin Statistics ----------
  app.get("/admin-stats", verifyJWT, async (req, res) => {
    try {
      const totalUsers = await usersCollection.countDocuments();
      const totalRequests = await donationRequests.countDocuments();
      const funds = await fundsCollection.find().toArray();

      const totalFunding = funds.reduce(
        (sum, fund) => sum + Number(fund.amountTotal || 0),
        0
      );

      res.send({
        totalUsers,
        totalRequests,
        totalFunding,
      });
    } catch (error) {
      console.error("Admin stats error:", error);
      res.status(500).send({ message: "Failed to load stats" });
    }
  });

  console.log("MongoDB Run");
}

run().catch(console.error);

// ---------- Base Route ----------
app.get("/", (req, res) => {
  res.send("Server Running");
});

// ---------- Start Server ----------
app.listen(port, host, () => {
  console.log(`Server running on port ${port}`);
});
