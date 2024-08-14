// populates dataabse with initial user data (dummy users)
let argon2 = require("argon2");
let { Pool } = require("pg");
let env = require("../../env.json");

let pool = new Pool(env);

let dummyUsers = [
  ["abc", "mycoolpassword"],
  ["admin", "root"],
  ["fiddlesticks", "bibblebap"],
];

pool.connect().then(async (client) => {
  for (let [username, password] of dummyUsers) {
    let hash;
    try {
      hash = await argon2.hash(password);
    } catch (error) {
      console.log(`Error hashing '${password}':`, error);
      continue;
    }

    try {
      await client.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hash]
      );
    } catch (error) {
      console.log(`Error inserting '${username}':`, error);
    }
    console.log(`Inserted ('${username}') with hash '${hash}'`);
  }

  let result = await client.query("SELECT * FROM users");
  console.log(result.rows);

  await client.release();
});
