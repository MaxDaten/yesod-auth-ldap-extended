{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

-- Plugin LDAP authentication for Yesod, based heavily on Yesod.Auth.Kerberos
-- and Yesod.Auth.Email
-- Verify that your LDAP installation can bind and return LDAP objects before
-- trying to use this module.


-- sample manual LDAP code here

module Yesod.Auth.LDAPExtended
    ( genericAuthLDAP 
    , YesodAuthLdap (..)
    , registerR 
    ) where

import System.Random

import Yesod.Auth
import Yesod.Auth.Message
import Web.Authenticate.LDAP
import LDAP
import qualified Data.Text as TS
import Data.Text.Lazy.Encoding (encodeUtf8)
import Network.Mail.Mime (randomString)
import Data.Text (Text)
import Text.Hamlet
import Text.Blaze (toHtml)
import Control.Monad.IO.Class (liftIO)
import Control.Applicative ((<$>), (<*>))

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)

import qualified Yesod.Auth.Message as Msg

registerR :: AuthRoute
registerR = PluginR "ldap" ["register"]

verify :: Text -> Text -> AuthRoute
verify eid verkey = PluginR "ldap" ["verify", eid, verkey]

type Email = Text
type VerKey = Text
type VerUrl = Text

class (YesodAuth m) => YesodAuthLdap m where
    --type AuthLdapId m
    sendVerifyEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()


genericAuthLDAP :: YesodAuthLdap m => LdapAuthConfig -> LdapBindConfig -> AuthPlugin m
genericAuthLDAP config bindConfig = AuthPlugin "ldap" dispatch $ \tm ->
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
    dispatch "POST" ["login"]       = postLoginR config bindConfig >>= sendResponse
    dispatch "GET"  ["register"]    = getRegisterR  >>= sendResponse
    dispatch "POST" ["register"]    = postRegisterR config bindConfig >>= sendResponse
    dispatch _ _              = notFound

login :: AuthRoute
login = PluginR "ldap" ["login"]


postLoginR :: (YesodAuthLdap master) => LdapAuthConfig -> LdapBindConfig -> GHandler Auth master ()
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
                                       (Credentials u p (TS.pack "")) -- todo empty mail -> Maybe
                                       bindConfig
          case result of
            AuthOk ldapEntries -> do
                 let creds = Creds
                       { credsIdent  = TS.pack $ ledn $ head ldapEntries -- TODO: make it better
                       , credsPlugin = "ldap"
                       , credsExtra  = []
                       }
                 setCreds True creds
            ldapError -> errorMessage (TS.pack $ show ldapError)

getRegisterR :: (YesodAuthLdap master) => GHandler Auth master RepHtml
getRegisterR = do
    toMaster <- getRouteToMaster
    defaultLayout $ do
        [whamlet|
<p>"ABC"
<form method="post" action="@{toMaster registerR}">
    <label for="email">"mail"
    <input type="email" name="email" width="150">
    <input type="submit" value="Reg">
|]

postRegisterR :: (YesodAuthLdap master) => LdapAuthConfig -> LdapBindConfig -> GHandler Auth master RepHtml
postRegisterR auth bind = do
    y <- getYesod
    email <- runInputPost $ ireq emailField "email"
    (EmailRes entry) <- liftIO $ getByEmail email auth bind
    (mid, verKey) <-
        case entry of
            -- verification entry already existing
            Just (Right key) -> return (email, key)
            
            -- already registered ? what to do? revalidate to set a new pw?
            Just (Left _) -> do
                --key <- liftIO $ randomKey y
                -- setVerifyKey lid key
                return (undefined)
                
            -- no entry existing
            Nothing -> do
                key <- liftIO $ randomKey y
                res <- liftIO $ addUnverifiedLDAP auth email key bind
                -- TODO: check results
                return (email, key)
    render <- getUrlRender
    tm <- getRouteToMaster
    let verUrl = render $ tm $ verify (toPathPiece mid) verKey
    sendVerifyEmail email verKey verUrl
    defaultLayout $ do
        setTitleI Msg.ConfirmationEmailSentTitle
        [whamlet| <p>_{Msg.ConfirmationEmailSent email} |]

{--
    utility functions
--}

-- | Generate a random alphanumeric string.
randomKey :: m -> IO Text
randomKey _ = do
    stdgen <- newStdGen
    return $ TS.pack $ fst $ randomString 10 stdgen
