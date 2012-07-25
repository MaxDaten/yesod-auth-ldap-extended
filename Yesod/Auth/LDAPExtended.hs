{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- Plugin LDAP authentication for Yesod, based heavily on Yesod.Auth.Kerberos
-- and Yesod.Auth.Email
-- Verify that your LDAP installation can bind and return LDAP objects before
-- trying to use this module.


-- sample manual LDAP code here

module Yesod.Auth.LDAPExtended
    ( genericAuthLDAP
    , YesodAuthLdap
    -- * routes
    , registerR
    , loginR
    , forgetR 
    , termsOfServiceR
    , privacyPolicyR
    -- * exposed modules
    --, module Yesod.Auth.Ldap.Handler
    , module Yesod.Auth.Ldap.YesodAuthLdap
    , module Yesod.Auth.Ldap.Handler.Password
    ) where

import System.Random

import Yesod.Auth
import Yesod.Auth.Message
import Yesod.Message (RenderMessage (..))
import Web.Authenticate.LDAP
import LDAP
import qualified Data.Text as TS
import Data.Text.Lazy.Encoding (encodeUtf8)
import Network.Mail.Mime (randomString)
import Data.Text (Text)
import Data.Maybe (fromJust)
import Text.Hamlet
import Text.Blaze (toMarkup)
import Control.Monad                 (when)  
import Control.Monad.IO.Class (liftIO)
import Control.Applicative ((<$>), (<*>))

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)

import qualified Yesod.Auth.Message as Msg
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

import Yesod.Auth.Ldap.Handler.Password
import Yesod.Auth.Ldap.YesodAuthLdap

registerR, loginR, forgetR, termsOfServiceR, privacyPolicyR :: AuthRoute
registerR   = PluginR "ldap" ["register"]
loginR      = PluginR "ldap" ["login"]
forgetR     = PluginR "ldap" ["forget-password"]
termsOfServiceR = PluginR "ldap" ["terms-of-service"]
privacyPolicyR  = PluginR "ldap" ["privacy-policy"]

verify :: Text -> Text -> AuthRoute
verify eid verkey = PluginR "ldap" ["verify", eid, verkey]



genericAuthLDAP :: YesodAuthLdap m
                => LdapAuthConfig 
                -> LdapBindConfig 
                -> AuthPlugin m
genericAuthLDAP config bindConfig = AuthPlugin "ldap" dispatch $ \tm ->
    [whamlet|
    <div id="header">
         <h1>_{Msg.LoginTitle}

    <div id="login">
        <form method="post" action="@{tm loginR}">
            <table>
                <tr>
                    <th>_{LdapM.Username}
                    <td>
                        <input id="x" name="username" autofocus="" required>
                <tr>
                    <th>_{Msg.Password}
                    <td>
                        <input type="password" name="password" required>
                <tr>
                    <td colspan="2">
                        <input type="submit" value=_{Msg.LoginTitle}>
            <div id=register>
                <a href="@{tm registerR}">_{Msg.RegisterLong}
            <div id=forget>
                <a href="@{tm forgetR}">_{LdapM.ForgetPassword}
            <script>
                if (!("autofocus" in document.createElement("input"))) {
                    document.getElementById("x").focus();
                }
|]
  where
    dispatch "POST" ["login"]       = postLoginR config bindConfig >>= sendResponse
    dispatch "GET"  ["register"]    = getRegisterR  >>= sendResponse
    dispatch "POST" ["register"]    = postRegisterR config bindConfig >>= sendResponse
    dispatch "GET"  ["verify", eid, verkey] =
        case fromPathPiece eid of
            Nothing -> notFound
            Just eid' -> getVerifyR eid' verkey config bindConfig >>= sendResponse
    
    dispatch "GET"  ["set-password"] = getNewUserR >>= sendResponse
    dispatch "POST" ["set-password"] = postNewUserR config bindConfig >>= sendResponse
    
    dispatch "GET"  ["change-password"] = getChangePassR >>= sendResponse
    dispatch "POST" ["change-password"] = postChangePassR config bindConfig >>= sendResponse
    
    dispatch "GET"  ["reset-password"] = getResetPassR >>= sendResponse
    dispatch "POST" ["reset-password"] = postResetPassR config bindConfig >>= sendResponse
    
    dispatch "GET"  ["forget-password"] = getForgetR >>= sendResponse
    dispatch "POST" ["forget-password"] = postForgetR config bindConfig >>= sendResponse

    dispatch "GET"  ["privacy-policy"] = getPrivacyPolicyR >>= sendResponse

    dispatch "GET"  ["terms-of-service"] = getTermsOfServiceR >>= sendResponse
    
    dispatch _ _              = notFound




postLoginR :: (YesodAuthLdap master)
            => LdapAuthConfig 
            -> LdapBindConfig 
            -> GHandler Auth master ()
postLoginR config bindConfig = do
    (mu,mp) <- runInputPost $ (,)
        <$> iopt textField "username"
        <*> iopt textField "password"

    let errorMessage (message :: Text) = do
        setMessage $ toMarkup message
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
            AuthOk [LDAPEntry _ attrs] -> do
                 [mail] <- return $ fromJust $ lookup "mail" attrs
                 let creds = Creds
                       { credsIdent  = TS.pack mail -- TODO: make it better
                       , credsPlugin = "ldap"
                       , credsExtra  = []
                       }
                 setCreds True creds
            err -> do
                setMessageI $ LdapM.LoginError err
                toMaster <- getRouteToMaster
                redirect $ toMaster LoginR



getRegisterR :: (YesodAuthLdap master) => GHandler Auth master RepHtml
getRegisterR = do
    toMaster <- getRouteToMaster
    defaultLayout $ do
        [whamlet|
<p>_{LdapM.EnterEmailLong}
<div id=disclaimer>
<p>Mit der Übermittlung deiner E-Mail Adresse stimmst du unseren <a href="@{toMaster termsOfServiceR}">Nutzungsbedingungen</a> und unseren <a href="@{toMaster privacyPolicyR}">Datenschutzbestimmungen</a> zu
<form method="post" action="@{toMaster registerR}">
    <label for="email">_{Msg.Email}
    <input type="email" name="email" width="150" required>
    <input type="submit" value=_{Msg.Register}>
|]



postRegisterR :: (YesodAuthLdap master) 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master RepHtml
postRegisterR auth bind = do
    y <- getYesod
    email <- runInputPost $ ireq emailField "email"
    
    e <- liftIO $ getByEmail email auth bind
    entry <- case e of
        (EmailRes en) -> return en
        _ -> do
            toMaster <- getRouteToMaster
            setMessageI LdapM.EmailAlreadyRegistered
            redirect $ toMaster forgetR
            
    (mid, verKey) <-
        case entry of
            -- verification entry already existing
            Just (Right key) -> return (email, key)
            
            -- already registered ? what to do? revalidate to set a new pw?
            Just (Left _) -> do
                toMaster <- getRouteToMaster
                setMessageI LdapM.EmailAlreadyRegistered
                redirect $ toMaster forgetR
            
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
        [whamlet| <p>_{LdapM.ConfirmationEmailSent email}
                  <p>
                        <strong>_{LdapM.ConfirmationEmailSentSpam}
        |]



-- TODO: first argument (email) to a specific YesodAuth (like the 'AuthEmailId' in Yesod.Auth.Email
getVerifyR :: YesodAuthLdap master 
           => Email 
           -> VerKey 
           -> LdapAuthConfig 
           -> LdapBindConfig 
           -> GHandler Auth master RepHtml
getVerifyR mail key auth bind = do
    mkey <- liftIO $ getEmailVKey mail auth bind
    case mkey of
        Nothing -> return ()
        Just realKey -> do
            case (realKey == key) of
                (True) -> do
                    liftIO $ removeUnverified key auth bind
                    setCreds False $ Creds "ldap" mail [("verifiedEmail", mail)]
                    
                    re <- liftIO $ getRegistered mail auth bind
                    
                    setMessageI Msg.AddressVerified
                    toMaster <- getRouteToMaster
                    case re of
                        Nothing -> do
                            redirect $ toMaster setpassR
                        Just _ -> do
                            redirect $ toMaster resetpassR
                _ -> return ()

        
    defaultLayout $ do
        setTitleI Msg.InvalidKey
        [whamlet| <p>_{Msg.InvalidKey} |]




    
getForgetR :: (YesodAuthLdap master) => GHandler Auth master RepHtml 
getForgetR = do
    toMaster <- getRouteToMaster
    defaultLayout $ do
        [whamlet|
<p>_{LdapM.ForgetLong}
<form method="post" action="@{toMaster forgetR}">
    <label for="email">_{Msg.Email}
    <input type="email" name="email" width="150">
    <input type="submit" value=_{LdapM.Send}>
|]

postForgetR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master RepHtml
postForgetR auth bind = do
    y <- getYesod
    email <- runInputPost $ ireq emailField "email"
    (EmailRes entry) <- liftIO $ getByEmail email auth bind
    (mid, verKey) <-
        case entry of
            -- verification entry already existing
            Just (Right key) -> return (email, key) -- TODO
            
            -- already registered ? what to do? revalidate to set a new pw?
            Just (Left _) -> do
                key <- liftIO $ randomKey y
                res <- liftIO $ addUnverifiedLDAP auth email key bind
                -- TODO: check results
                return (email, key)
            
            -- no entry existing
            Nothing -> do
                toMaster <- getRouteToMaster
                setMessageI LdapM.EmailNotRegistered
                redirect $ toMaster registerR
                
    render <- getUrlRender
    tm <- getRouteToMaster
    let verUrl = render $ tm $ verify (toPathPiece mid) verKey
    sendForgetEmail email verKey verUrl
    setMessageI Msg.ConfirmationEmailSentTitle
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
