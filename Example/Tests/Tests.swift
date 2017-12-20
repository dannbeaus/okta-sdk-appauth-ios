import UIKit
import XCTest
@testable import OktaAuth
@testable import AppAuth
@testable import Vinculum

class Tests: XCTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
        OktaAuth.tokens?.clear()
    }

    func testPListFailure() {
        // Attempt to find a plist file that does not exist
        XCTAssertNil(Utils.getPlistConfiguration(forResourceName: "noFile"))
    }

    func testPListFound() {
        // Attempt to find the Okta.plist file
        XCTAssertNotNil(Utils.getPlistConfiguration())
    }

    func testPListFormatWithTrailingSlash() {
        // Validate the PList issuer
        let dict = [
            "issuer": "https://example.com/oauth2/authServerId/"
        ]
        let issuer = Utils.removeTrailingSlash(dict["issuer"]!)
        XCTAssertEqual(issuer, "https://example.com/oauth2/authServerId")
    }

    func testPListFormatWithoutTrailingSlash() {
        // Validate the PList issuer
        let dict = [
            "issuer": "https://example.com/oauth2/authServerId"
        ]
        let issuer = Utils.removeTrailingSlash(dict["issuer"]!)
        XCTAssertEqual(issuer, "https://example.com/oauth2/authServerId")
    }

    func testValidScopesString() {
        // Validate the scopes are in the correct format
        let scopes = "openid profile email"
        let validScopes = ["openid", "profile", "email"]
        let scrubbedScopes = Utils.scrubScopes(scopes)
        XCTAssertEqual(scrubbedScopes, validScopes)
    }

    func testAddingOpenIDScopes() {
        // Validate that scopes not including "openid" get appended
        let scopes = "profile email"
        XCTAssertEqual(Utils.scrubScopes(scopes), ["profile", "email", "openid"])
    }

    func testPasswordFailureFlow() {
        // Validate the username & password flow fails without clientSecret
        _ = Utils.getPlistConfiguration(forResourceName: "Okta-PasswordFlow")

        let pwdExpectation = expectation(description: "Will error attempting username/password auth")

        OktaAuth
            .login("user@example.com", password: "password")
            .start(withPListConfig: "Okta-PasswordFlow", view: UIViewController()) { response, error in
                XCTAssertEqual(
                    error!.localizedDescription,
                    "Authorization Error: The operation couldn’t be completed. (org.openid.appauth.general error -6.)"
                )
                pwdExpectation.fulfill()
        }

        waitForExpectations(timeout: 3, handler: { error in
            // Fail on timeout
            if error != nil { XCTFail(error!.localizedDescription) }
       })
    }

    func testIntrospectionEndpointURL() {
        // Similar use case for revoke and userinfo endpoints
        OktaAuth.configuration = [
            "issuer": "https://example.com"
        ]
        let url = Introspect().getIntrospectionEndpoint()
        XCTAssertEqual(url?.absoluteString, "https://example.com/oauth2/v1/introspect")
    }

    func testIntrospectionEndpointURLWithOAuth2() {
        // Similar use case for revoke and userinfo endpoints
        OktaAuth.configuration = [
            "issuer": "https://example.com/oauth2/default"
        ]
        let url = Introspect().getIntrospectionEndpoint()
        XCTAssertEqual(url?.absoluteString, "https://example.com/oauth2/default/v1/introspect")
    }

    func testUserInfoWithoutToken() {
        // Verify an error is returned if the accessToken is not included
        OktaAuth.configuration = [
            "issuer": "https://example.com/oauth2/default"
        ]
        
        let _ = UserInfo(token: nil) { response, error in
            XCTAssertEqual(error?.localizedDescription, "Missing Bearer token. You must authenticate first.")
        }
    }

    func testRevokeWithoutToken() {
        // Verify an error is returned if the accessToken is not included
        OktaAuth.configuration = [
            "issuer": "https://example.com/oauth2/default"
        ]

        let _ = Revoke(token: nil) { response, error in
            XCTAssertEqual(error?.localizedDescription, "Missing Bearer token. You must authenticate first.")
        }
    }

    func testIsAuthenticated() {
        // Validate that if there is an existing accessToken, we return an "authenticated" state
        let mockAuthState = OIDAuthState.init(authorizationResponse: nil, tokenResponse: nil, registrationResponse: nil)
        let tokenManager = OktaTokenManager(
            authState: mockAuthState,
            issuer: "https://example.com",
            clientId: "abc123"
        )
        OktaAuthorization().storeAuthState(tokenManager)
        // Should return 'false'
        let isAuth = OktaAuth.isAuthenticated()
        XCTAssertFalse(isAuth)
    }
}
