import Vapor
import HTTP
import Auth
import Turnstile
import TurnstileWeb
import TurnstileCrypto

final class LoginController {
    func addRoutes(to drop: Droplet) {
        drop.post("login", handler: adminLogin)
        drop.post("register", handler: createAdmin)
        
        if let clientID = drop.config["app", "facebookClientID"]?.string,
            let clientSecret = drop.config["app", "facebookClientSecret"]?.string {
            
            let facebook = Facebook(clientID: clientID, clientSecret: clientSecret)
            
            drop.get("login", "facebook") { request in
                let state = URandom().secureToken
                let response = Response(redirect: facebook.getLoginLink(redirectURL: request.baseURL + "/login/facebook/consumer", state: state).absoluteString)
                response.cookies["OAuthState"] = state
                return response
            }
            
            drop.get("login", "facebook", "consumer") { request in
                guard let state = request.cookies["OAuthState"] else {
                    return Response(redirect: "/login")
                }
                let account = try facebook.authenticate(authorizationCodeCallbackURL: request.uri.description, state: state) as! FacebookAccount
                try request.auth.login(account)
                return Response(redirect: "/")
            }
            
        } else {
            drop.get("login", "facebook", handler: { (request) -> ResponseRepresentable in
                return "You need to configure Facebook Login first!"
            })
        }
    }
  
    func createAdmin(_ request: Request)throws -> ResponseRepresentable {
        guard let username = request.data["username"]?.string,
            let password = request.data["password"]?.string else {
                throw Abort.badRequest
        }
        
        let creds = UsernamePassword(username: username, password: password)
        var user = try User.register(credentials: creds) as? User
        if user != nil {
            try user!.save()
            return Response(redirect: "/user/\(user!.username)")
        } else {
            return Response(redirect: "/create-admin")
        }
    }
  
    func adminLogin(_ request: Request)throws -> ResponseRepresentable {
        guard let username = request.data["username"]?.string,
            let password = request.data["password"]?.string else {
                throw Abort.badRequest
        }
        
        let credentials = UsernamePassword(username: username, password: password)
        do {
            try request.auth.login(credentials, persist: true)
            return Response(redirect: "/admin/new-post")
        } catch {
            return Response(redirect: "/login?succeded=false")
        }
    }
}
