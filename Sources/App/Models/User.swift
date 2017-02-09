import Vapor
import VaporPostgreSQL
import Fluent
import Auth
import Turnstile
import TurnstileWeb
import BCrypt

final class User {
    var id: Node?
    var username: String
    var password: String
    var facebookID = ""
    var googleID = ""
    
    init(username: String, password: String) {
        self.id = nil
        self.username = username
        self.password = password
    }
    
    init(node: Node, in context: Context) throws {
        id = try node.extract("id")
        username = try node.extract("username")
        password = try node.extract("password")
    }
}

extension User: Model {
    func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            "id": id,
            "username": username,
            "password": password
            ])
    }
}

extension User: Preparation {
    static func prepare(_ database: Database) throws {
        try database.create("users", closure: { (user) in
            user.id()
            user.string("username")
            user.string("password")
        })
    }
    
    static func revert(_ database: Database) throws {
        try database.delete("users")
    }
}

extension User: Auth.User {
    static func authenticate(credentials: Credentials) throws -> Auth.User {
        switch credentials {
        case let id as Identifier:
            guard let user = try User.find(id.id) else {
                throw Abort.custom(status: .forbidden, message: "Invalid user identifier.")
            }
            
            return user
            
        case let usernamePassword as UsernamePassword:
            let fetchedUser = try User.query().filter("username", usernamePassword.username).first()
            guard let user = fetchedUser else {
                throw Abort.custom(status: .networkAuthenticationRequired, message: "User does not exist")
            }
            if try BCrypt.verify(password: usernamePassword.password, matchesHash: fetchedUser!.password) {
                return user
            } else {
                throw Abort.custom(status: .networkAuthenticationRequired, message: "Invalid user name or password.")
            }
            
            
        default:
            let type = type(of: credentials)
            throw Abort.custom(status: .forbidden, message: "Unsupported credential type: \(type).")
        }
    }
    static func register(credentials: Credentials) throws -> Auth.User {
        let usernamePassword = credentials as? UsernamePassword
        
        guard let creds = usernamePassword else {
            let type = type(of: credentials)
            throw Abort.custom(status: .forbidden, message: "Unsupported credential type: \(type).")
        }
        
        let user = User(username: creds.username, password: BCrypt.hash(password: creds.password))
        return user
    }
}
