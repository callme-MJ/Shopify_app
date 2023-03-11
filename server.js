const dotenv = require('dotenv');
const Shopify  = require('shopify-api-node');
const crypto = require("crypto");
const request = require("request-promise");
const querystring = require("querystring");
const cookie = require("cookie");
const express = require("express");
const nonce = require("nonce");

const scopes = "read_products,write_products";

const forwardingAddress = "https://6fd5-117-216-159-203.in.ngrok.io";
const shop = "MJTestStore_Assignment"
shopState = nonce();
const redirectURL = forwardingAddress + "/shopify/callback";
const apiKey = "b369eb841657f4fc58f24bb00e4951a4";
const password = "6b09e69c6f93aa759ca3b2972744070e";

dotenv.config();
const { SHOP_NAME, API_KEY, PASSWORD } = process.env;

const app = express();

app.get('/', (req, res) => {
  res.send('Hello, World!');
});


app.get("/shopify", (req, res) => {
  const shopName = "mjteststore-assignment.myshopify.com"
   
    const installUrl =
      "https://" +
      shopName +
      "/admin/oauth/authorize?client_id=" +
      apiKey +
      "&scope=" +
      scopes +
      "&state=" +
      shopState +
      "&redirect_uri=" +
      redirectURL;

    res.cookie("state", shopState);
    res.redirect(installUrl);
   
});
  
  app.get("/shopify/callback", (req, res) => {
    const { shop, hmac, code, shopState } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).shopState;
  
    if (shopState !== stateCookie) {
      return res.status(400).send("request origin cannot be found");
    }
  
    if (shop && hmac && code) {
      const Map = Object.assign({}, req.query);
      delete Map["hmac"];
      delete Map["signature"];
  
      const message = querystring.stringify(Map);
      const providedHmac = Buffer.from(hmac, "utf-8");
      const generatedHash = Buffer.from(
        crypto
          .createHmac("sh256", password)
          .update(message)
          .digest("hex"),
        "utf-8"
      );
      let hashEquals = false;
      try {
        hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
      } catch (e) {
        hashEquals = false;
      }
      if (!hashEquals) {
        return res.status(400).send("HMAC validation failed");
      }
      const accessTokenRequestUrl =
        "https://" + shop + "/admin/oauth/access_token";
      const accessTokenPayload = {
        client_id: apiKey,
        client_secret: password,
        code,
      };
      request
        .post(accessTokenRequestUrl, { json: accessTokenPayload })
  
        .then((accessTokenResponse) => {
          const accessToken = accessTokenResponse.access_token;
  
          const apiRequestURL = `https:// + ${shop} + /admin/shop.json`;
  
          const apiRequestHeaders = {
            "X-Shopify-Access-Token": accessToken,
          };
  
          request
            .get(apiRequestURL, { headers: apiRequestHeaders })
  
            .then((apiResponse) => {
              res.end(apiResponse);
            })
  
            .catch((error) => {
              res.status(error.statusCode).send(error.error.error_description);
            });
        })
  
        .catch((error) => {
          res.status(error.statusCode).send(error.error.error_description);
        });
    } else {
      return res.status(400).send("required parameter missing");
    }
  });

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
