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
    , YesodAuthLdap (..)
    , registerR 
    , setpassR
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
import Text.Blaze (toHtml)
import Control.Monad                 (when)  
import Control.Monad.IO.Class (liftIO)
import Control.Applicative ((<$>), (<*>))

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)

import qualified Yesod.Auth.Message as Msg
import Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

registerR, setpassR :: AuthRoute
registerR   = PluginR "ldap" ["register"]
setpassR    = PluginR "ldap" ["set-password"]

verify :: Text -> Text -> AuthRoute
verify eid verkey = PluginR "ldap" ["verify", eid, verkey]

type Email  = Text
type VerKey = Text
type VerUrl = Text
type Pass   = Text

newUserSKey :: Text
newUserSKey = "_NEWUSER"

class (YesodAuth m, RenderMessage m FormMessage) => YesodAuthLdap m where
    --type AuthLdapId m
    sendVerifyEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()
    register        :: Email -> Pass -> AuthId m -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPRegResult)
    updatePassword  :: AuthId m -> Pass -> Pass -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPPassUpdateResult)
    
    renderLdapMessage :: m -> [Text] -> LdapMessage -> Text
    renderLdapMessage _ _ = LdapM.defaultMessage


genericAuthLDAP :: YesodAuthLdap m
                => LdapAuthConfig 
                -> LdapBindConfig 
                -> AuthPlugin m
genericAuthLDAP config bindConfig = AuthPlugin "ldap" dispatch $ \tm ->
    [whamlet|
    <div id="header">
         <h1>_{Msg.LoginTitle}

    <div id="login">
        <form method="post" action="@{tm login}">
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
                    <td>&nbsp;
                    <td>
                        <input type="submit" value=_{Msg.LoginTitle}>

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
    
    dispatch "GET"  ["set-password"] = getPasswordR >>= sendResponse
    dispatch "POST" ["set-password"] = postPasswordR config bindConfig >>= sendResponse
    
    dispatch _ _              = notFound

login :: AuthRoute
login = PluginR "ldap" ["login"]



postLoginR :: (YesodAuthLdap master)
            => LdapAuthConfig 
            -> LdapBindConfig 
            -> GHandler Auth master ()
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
            AuthOk [LDAPEntry _ attrs] -> do
                 [mail] <- return $ fromJust $ lookup "mail" attrs
                 let creds = Creds
                       { credsIdent  = TS.pack mail -- TODO: make it better
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
<p>_{Msg.EnterEmail}
<form method="post" action="@{toMaster registerR}">
    <label for="email">_{Msg.Email}
    <input type="email" name="email" width="150">
    <input type="submit" value=_{Msg.Register}>
|]



postRegisterR :: (YesodAuthLdap master) 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master RepHtml
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
                toMaster <- getRouteToMaster
                setMessageI LdapM.EmailAlreadyRegistered
                redirect $ toMaster LoginR
            
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



-- TODO: first argument (email) to a specific YesodAuth (like the 'AuthEmailId' in Yesod.Auth.Email
getVerifyR :: YesodAuthLdap master 
           => Email 
           -> VerKey 
           -> LdapAuthConfig 
           -> LdapBindConfig 
           -> GHandler Auth master RepHtml
getVerifyR mail key auth bind = do
    (EmailRes entry) <- liftIO $ getByEmail mail auth bind
    case entry of
         -- already verified registered
        Just (Left _) -> return ()
        Just (Right realKey) -> do
            
            case (realKey == key) of
                (True) -> do
                    liftIO $ removeUnverified key auth bind
                    setCreds False $ Creds "ldap" mail [("verifiedEmail", mail)]
                    setSession newUserSKey mail
                    toMaster <- getRouteToMaster
                    setMessageI Msg.AddressVerified
                    redirect $ toMaster setpassR
                _ -> return ()
        _ -> return ()
        
    defaultLayout $ do
        setTitleI Msg.InvalidKey
        [whamlet| <p>_{Msg.InvalidKey} |]



getPasswordR :: YesodAuthLdap master 
             => GHandler Auth master RepHtml
getPasswordR = do
    toMaster <- getRouteToMaster
    maid <- maybeAuthId
    case maid of
        Just _ -> return ()
        Nothing -> do
            setMessageI Msg.BadSetPass
            redirect $ toMaster LoginR
            
    v <- lookupSession newUserSKey
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
$maybe _ <- v
    <h3>_{Msg.Register}
$nothing
    <h3>_{Msg.SetPassTitle}
<form method="post" action="@{toMaster setpassR}">
    <table>
        $maybe _ <- v
            <tr>
                <th>_{LdapM.Username}
                <td>
                    <input type="text" name="username">
        $nothing
            <tr>
                <th>_{LdapM.OldPassword}
                <td>
                    <input type="password" name="old">
            
        <tr>
            <th>_{Msg.NewPass}
            <td>
                <input type="password" name="new">
        <tr>
            <th>_{Msg.ConfirmPass}
            <td>
                <input type="password" name="confirm">
        <tr>
            <td colspan="2">
                $maybe _ <- v
                    <input type="submit" value=_{Msg.Register}>
                $nothing
                    <input type="submit" value=_{Msg.ConfirmPass}>
|]



postPasswordR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postPasswordR auth bind = do
    newU <- lookupSession newUserSKey

    toMaster <- getRouteToMaster
    y <- getYesod
    
    maid <- maybeAuthId
    aid <- case maid of
            Nothing -> do
                setMessageI Msg.BadSetPass
                redirect $ toMaster LoginR
            Just aid -> return aid
    
    case newU of
         (Just _) -> do
            (username, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "username"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster setpassR
            
            res <- register username new aid auth bind
            case res of
                RegOk        -> return ()
                UsernameUsed -> do
                                setMessageI $ RegistrationError UsernameUsed username
                                redirect $ toMaster setpassR                    
                e            -> do
                                setMessageI $ RegistrationError e username
                                redirect $ toMaster LoginR
                            
            deleteSession newUserSKey
         Nothing -> do
            (old, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "old"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster setpassR
                
            res <- updatePassword aid old new auth bind
            
            case res of
                 PassUpdateOk -> return ()
                 e -> do
                     setMessageI $ PasswordUpdateError e
                     redirect $ loginDest y
                 
    
    
    setMessageI Msg.PassUpdated
    redirect $ loginDest y

{--
    utility functions
--}

-- | Generate a random alphanumeric string.
randomKey :: m -> IO Text
randomKey _ = do
    stdgen <- newStdGen
    return $ TS.pack $ fst $ randomString 10 stdgen

instance YesodAuthLdap m => RenderMessage m LdapMessage where
    renderMessage = renderLdapMessage