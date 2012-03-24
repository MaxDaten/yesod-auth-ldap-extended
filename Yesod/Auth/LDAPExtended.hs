{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

-- Plugin LDAP authentication for Yesod, based heavily on Yesod.Auth.Kerberos
-- and Yesod.Auth.Email
-- Verify that your LDAP installation can bind and return LDAP objects before
-- trying to use this module.


-- sample manual LDAP code here

module Yesod.Auth.LDAPExtended
    ( genericAuthLDAP ) where

import Yesod.Auth
import Yesod.Auth.Message
import Web.Authenticate.LDAP
import LDAP
import Data.Text (Text,pack,unpack)
import Text.Hamlet
import Text.Blaze (toHtml)
import Control.Monad.IO.Class (liftIO)
import Control.Applicative ((<$>), (<*>))

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)


genericAuthLDAP :: YesodAuth m => LdapAuthConfig -> LdapBindConfig -> AuthPlugin m
genericAuthLDAP config bindConfig = AuthPlugin "LDAP" dispatch $ \tm ->
    [whamlet|
    <div id="header">
         <h1>Login

    <div id="login">
        <form method="post" action="@{tm login}">
            <table>
                <tr>
                    <th>Username:
                    <td>
                        <input id="x" name="username" autofocus="" required>
                <tr>
                    <th>Password:
                    <td>
                        <input type="password" name="password" required>
                <tr>
                    <td>&nbsp;
                    <td>
                        <input type="submit" value="Login">

            <script>
                if (!("autofocus" in document.createElement("input"))) {
                    document.getElementById("x").focus();
                }
|]
  where
    dispatch "POST" ["login"] = postLoginR config bindConfig >>= sendResponse
    dispatch _ _              = notFound

login :: AuthRoute
login = PluginR "LDAP" ["login"]


postLoginR :: (YesodAuth y) => LdapAuthConfig -> LdapBindConfig -> GHandler Auth y ()
postLoginR config bindConfig = do
    (mu,mp) <- runInputPost $ (,)
        <$> iopt textField "username"
        <*> iopt textField "password"

    let errorMessage (message :: Text) = do
        setMessage $ toHtml message
        toMaster <- getRouteToMaster
        redirect $ toMaster LoginR

    case (mu,mp) of
        (Nothing, _      ) -> do
            mr <- getMessageRender
            errorMessage $ mr PleaseProvideUsername
        (_      , Nothing) -> do
            mr <- getMessageRender
            errorMessage $ mr PleaseProvidePassword
        (Just u , Just p ) -> do
          result <- liftIO $ loginLDAP config 
                                       (Credentials u p (pack "")) -- todo empty mail -> Maybe
                                       bindConfig
          case result of
            AuthOk ldapEntries -> do
                 let creds = Creds
                       { credsIdent  = pack $ ledn $ head ldapEntries 
                       , credsPlugin = "LDAP"
                       , credsExtra  = []
                       }
                 setCreds True creds
            ldapError -> errorMessage (pack $ show ldapError)

