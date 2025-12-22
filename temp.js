require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// Middleware
app.use(
  cors({
    origin: [process.env.CLIENT_DOMAIN],
    credentials: true,
  })
);

app.use(express.json());

// ----------- JWT Middlewares  ----------- //
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  console.log(token);
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    console.log(decoded);
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// ----------- MongoDB Area  ----------- //

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db("droplinksDB");
    const usersCollection = db.collection("users");
    const donationRequestsCollections = db.collection("donationRequests");
    const fundsCollections = db.collection("funds");

    // ----------- User Role Middlewares  ----------- //
    const verifyAdmin = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "admin")
        return res
          .status(403)
          .send({ message: "Admin only Actions!", role: user?.role });

      next();
    };
    const verifyVolunteer = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "volunteer")
        return res
          .status(403)
          .send({ message: "volunteer only Actions!", role: user?.role });

      next();
    };
    const verifyDonor = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "donor")
        return res
          .status(403)
          .send({ message: "Donor only Actions!", role: user?.role });

      next();
    };

    //  ------------  Active User Middlewares ------------  //
    const verifyActiveUser = async (req, res, next) => {
      const email = req.tokenEmail;

      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      if (user.status === "blocked") {
        return res.status(403).send({
          message: "Your account has been blocked. Contact admin.",
        });
      }

      next();
    };

    //  ------------  Users Data in the DB  ------------  //

    app.post("/user", async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      userData.role = "donor";
      userData.status = "active";

      const query = {
        email: userData.email,
      };

      const userExists = await usersCollection.findOne(query);
      console.log("User Exists---> ", !!userExists);

      if (userExists) {
        console.log("Updating user info...");
        const result = await usersCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      console.log("Saving new user...");
      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });
    // User Get
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const adminEmail = req.tokenEmail;
      const users = await usersCollection
        .find({ email: { $ne: adminEmail } }) //Exclude cureent admin
        .toArray();
      res.send(users);
    });

    // User User Role and Status //
    app.patch("/update-role", verifyJWT, verifyAdmin, async (req, res) => {
      const { email, role, status } = req.body;

      if (!email || !role || !status) {
        return res.status(400);
      }

      const result = await usersCollection.updateOne(
        { email },
        { $set: { role: role.toLowerCase(), status: status.toLowerCase() } }
      );
      if (result.matchedCount === 0) {
        return res.status(404).send({ message: "User not found" });
      }
      res.send({ result });
    });

    // User Role Getting
    app.get("/user/role", verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role });
    });

    //  ------------  Save Donation Requests in the DB ------------ //
    app.post("/donation-requests", async (req, res) => {
      const donationRequests = req.body;
      console.log(donationRequests);
      const result = await donationRequestsCollections.insertOne(
        donationRequests
      );
      res.send(result);
    });

    //  ------------  Get All Donation Requests from DB ------------ //

    app.get("/donation-requests", verifyJWT, async (req, res) => {
      const result = await donationRequestsCollections.find().toArray();
      res.send(result);
    });
    //  ------------  Get Pending Donation Requests from DB ------------ //

    app.get("/donation-requests/pending", async (req, res) => {
      try {
        const pendingRequests = await donationRequestsCollections
          .find({ status: "Pending" })
          .toArray();
        res.send(pendingRequests);
      } catch (error) {
        console.error("Error fetching pending donation requests:", error);
        res
          .status(500)
          .send({ message: "Failed to fetch pending requests", error });
      }
    });

    //  ------------  Edit Donation Requests Data ------------ //
    app.patch("/donation-requests/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;

      delete updatedData._id;

      try {
        const result = await donationRequestsCollections.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Update failed" });
      }
    });

    //  ------------  Update Donation Request Status by ID ------------ //
    app.patch("/donation-requests", async (req, res) => {
      const { id, status } = req.body;

      if (!id || !status) {
        return res
          .status(400)
          .send({ message: "Request ID and status are required" });
      }

      try {
        const result = await donationRequestsCollections.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ message: "Request not found or already has this status" });
        }

        res.send({ message: "Status updated successfully" });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to update status", error });
      }
    });

    //  ------------  Delete Donation Request Status by ID ------------ //
    app.delete("/donation-requests/:id", async (req, res) => {
      const result = await donationRequestsCollections.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    //  ------------  Get My Donation Requests from DB ------------ //

    app.get("/my-donation-requests", verifyJWT, async (req, res) => {
      const result = await donationRequestsCollections
        .find({ requesterEmail: req.tokenEmail })
        .toArray();
      res.send(result);
    });

    //  ------------  Get all Donation Requests DETAILS from DB ------------ //

    app.get("/donation-requests/:id", async (req, res) => {
      const id = req.params.id;
      const result = await donationRequestsCollections.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    //  ------------  PAYMENT GATEWAY ------------ //
    app.post("/create-checkout-session", async (req, res) => {
      const fundInfo = req.body;
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        customer_email: fundInfo.email,
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: fundInfo.amount * 100,
              product_data: {
                name: "Fund Deposit",
              },
            },
            quantity: 1,
          },
        ],
        metadata: {
          customerEmail: fundInfo.email,
          customerName: fundInfo.name,
          customerImage: fundInfo.image,
        },
        success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/funding`,
      });

      res.send({ url: session.url });
    });
    // PAYMENT SUCCESS Info
    app.post("/payment-success", async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      const fundCheck = await fundsCollections.findOne({
        transactionId: session.payment_intent,
      });

      if (session.status === "complete" && !fundCheck) {
        const paymentDate = new Date(session.created * 1000);
        const formattedDate = paymentDate.toLocaleString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
          // hour: "numeric",
          // minute: "numeric",
          // hour12: true,
        });

        // save data
        const fundInfo = {
          transactionId: session.payment_intent,
          payerName: session.customer_details?.name,
          payerImage: session.metadata.customerImage,
          payerEmail: session.customer_details?.email,
          amountTotal: session.amount_total / 100,

          paymentDate: formattedDate,
        };
        const result = await fundsCollections.insertOne(fundInfo);
      }
      res.send();
    });

    // get the Funds Data

    app.get("/funds", async (req, res) => {
      try {
        const funds = await fundsCollections.find().toArray();
        res.send(funds);
      } catch (error) {
        console.error("Error fetching funds:", error);
        res.status(500).send({ error: "Failed to fetch funds" });
      }
    });

    // ************** Send a ping to confirm a successful connection ************* //
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

// ----------- Base Route   ----------- //

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// ----------- Start Server   ----------- //

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
