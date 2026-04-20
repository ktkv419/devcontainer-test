const express = require("express")
const db = require("./db")
const bcr = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")

const app = express()
app.use(cors())
app.use(express.json())

const SECRET = "asdasdasdasdzasd"

const PORT = 3000

const auth = (req, res, next) => {
    const authHeader = req.headers.authorization
    if (!authHeader) return res.status(401).json({ error: "No token provided" })

    const token = authHeader.split(" ")[1] // ["Bearer", "eyDCjsakdj"]
    if (!token) return res.status(401).json({ error: "Invalid token form" })

    try {
        const decoded = jwt.verify(token, SECRET)
        req.user = decoded
        next()
    } catch (error) {
        return res.status(403).json({ error: "Invalid or expired token" })
    }
}

app.get("/", (req, res) => {
    return res.status(200).json({ text: "hello world" })
})

app.post("/auth/signin", (req, res) => {
    try {
        const { username, password } = req.body
        // проверьте наличие этих переменный
        // если нет, верните 400 с ошибкой

        if (!username || !password) return res.status(400).json({ error: "Missing data" })

        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username)

        if (!user) return res.status(401).json({ error: "Wrong password" })

        const valid = bcr.compareSync(password, user.password)

        // если valid - false 401 и неправильный пароль
        if (!valid) return res.status(401).json({ error: "Wrong password" })

        const { password: _, safeUser } = user
        const token = jwt.sign(safeUser, SECRET, { expiresIn: "24h" })
        res.status(200).json({ success: true, token, user: safeUser })
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Something went wrong" })
    }
})

app.post("/auth/signup", (req, res) => {
    try {
        const { username, password, email } = req.body

        if (!username || !password) {
            return res.status(400).json({ error: "." })
        }

        if (username.length < 3) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }

        const existing = db.prepare(
            "SELECT id FROM users WHERE username = ?"
        ).get(username)

        if (existing) return res.status(409).json({ error: "Пользователь уже существует" })

        const salt = bcr.genSaltSync(10)
        const hash = bcr.hashSync(password, salt)
        const role = "user"

        const info = db.prepare(`INSERT INTO users (username, email, password, role)
            VALUES(?,?,?,?)`).run(username.trim(), email.trim(), hash, role)

        const newUser = db.prepare(`SELECT * FROM users WHERE id = ?`).get(info.lastInsertRowid)

        const { password: _, ...safeUser } = newUser

        const token = jwt.sign({ ...safeUser }, SECRET, { expiresIn: "24h" })
        res.status(201).json({ success: true, token, user: safeUser })
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Server failed" })
    }
})

app.get("/api/items", (req, res) => {
    try {
        const items = db.prepare(
            "SELECT * FROM items ORDER BY createAt DESC"
        ).all()

        return res.status(200).json(items)
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Failed to fetch" })
    }
})

app.post("/api/items", auth, (req, res) => {
    console.log(req.body)
    try {
        const { title, description, price, imageUrl } = req.body

        if (!title || !title.trim()) {
            return res
                .status(400)
                .json({ error: "Нужно название" })
        }

        if (!description || !description.trim()) {
            return res
                .status(400)
                .json({ error: "Нужно описание" })
        }

        if (!price || price <= 0) {
            return res
                .status(400)
                .json({ error: "Нужна цена" })
        }

        const info = db.prepare(`
            INSERT INTO items (title, description, price, imageUrl, userId, username, status, highestBid, bidCount)
            VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, 0)
            `).run(title.trim(), description.trim(),
            parseFloat(price), imageUrl || null,
            req.user.id, req.user.username)

        const newItem = db
            .prepare("SELECT * FROM items WHERE id = ?")
            .get(info.lastInsertRowid)

        return res.status(201).json(newItem)
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Failed to create" })
    }
})

app.delete("/api/items/:id", auth, (req, res) => {
    try {
        const { id } = req.params
        if (!id) return res
            .status(401)
            .json({ error: "Missing ID" })

        const item = db
            .prepare("SELECT * FROM items WHERE id = ?")
            .get(id)

        if (!item) res.status(404).json({ error: "Missing item" })

        if (!(item.userId === req.user.id))
            return res
                .status(403)
                .json({ error: "Can't delete other users' post" })

        const info = db
            .prepare("DELETE FROM items WHERE id = ?")
            .run(id)

        return res.status(200).json({message: "Deleted"})
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Something went wrong" })
    }
})

app.listen(PORT)









// const a = [1, 2, 3]
// const b = a
// b.push(4)
// console.log(a)


// let a = 1
// let b = 1
// b = b + 1
// console.log(a)

// const a = [1, 2, 3]
// const b = [1, 2, 3]
// console.log(a === b)


// const user = {
//     username: "ktkv",
//     age: 25,
//     hobbies: ["coding"]
// }

// const { username, ...newUser } = user

// https://kitek.ktkv.dev - 12.32.123 
// https://ktkv.dev - 91.114.23.31
// https://kitek.ktkv.dev/feedback/api/items/1235432?username=ktkv&password=dsa