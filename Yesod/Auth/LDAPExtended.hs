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
    , changepassR
    , resetpassR
    , loginR
    , forgetR 
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
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

registerR, setpassR, changepassR, resetpassR, loginR, forgetR :: AuthRoute
registerR   = PluginR "ldap" ["register"]
setpassR    = PluginR "ldap" ["set-password"]
resetpassR  = PluginR "ldap" ["reset-password"]
changepassR = PluginR "ldap" ["change-password"]
loginR      = PluginR "ldap" ["login"]
forgetR     = PluginR "ldap" ["forget-password"]

verify :: Text -> Text -> AuthRoute
verify eid verkey = PluginR "ldap" ["verify", eid, verkey]

type Email  = Text
type VerKey = Text
type VerUrl = Text
type Pass   = Text

newUserSKey, forgetSKey :: Text
newUserSKey = "_NEWUSER"
forgetSKey  = "_FORGET"

data SetPasswordState = NewUser
                      | ResetPassword
                      | ChangePassword

class (YesodAuth m, RenderMessage m FormMessage) => YesodAuthLdap m where
    --type AuthLdapId m
    sendVerifyEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()
    sendForgetEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()
    register        :: Email -> Pass -> AuthId m -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPRegResult)
    updatePassword  :: AuthId m -> Pass -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPPassUpdateResult)
    login :: AuthId m -> Pass -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (Bool)
    
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
    
    dispatch "GET"  ["set-password"] = getPasswordR NewUser >>= sendResponse
    dispatch "POST" ["set-password"] = postPasswordR NewUser config bindConfig >>= sendResponse
    
    dispatch "GET"  ["change-password"] = getPasswordR ChangePassword >>= sendResponse
    dispatch "POST" ["change-password"] = postPasswordR ChangePassword config bindConfig >>= sendResponse
    
    dispatch "GET"  ["reset-password"] = getPasswordR ResetPassword >>= sendResponse
    dispatch "POST" ["reset-password"] = postPasswordR ResetPassword config bindConfig >>= sendResponse
    
    dispatch "GET"  ["forget-password"] = getForgetR >>= sendResponse
    dispatch "POST" ["forget-password"] = postForgetR config bindConfig >>= sendResponse
    
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
        [whamlet| <p>_{Msg.ConfirmationEmailSent email} |]



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



getPasswordR :: YesodAuthLdap master 
             => SetPasswordState
             -> GHandler Auth master RepHtml
getPasswordR state = do
    v <- lookupSession newUserSKey
    deleteSession newUserSKey
    
    toMaster <- getRouteToMaster
    maid <- maybeAuthId
    case maid of
        Just _ -> return ()
        Nothing -> do
            setMessageI Msg.BadSetPass
            redirect $ toMaster LoginR
            


    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
$case state
    $of NewUser
        <h3>_{Msg.Register}
        <form method="post" action="@{toMaster setpassR}">
            <table>
                <tr>
                    <th>_{LdapM.Username}
                    <td>
                        <input type="text" name="username">
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
                            <input type="hidden" name="regstate" value=state>
                            <input type="submit" value=_{Msg.Register}>
    $of ChangePassword
        <h3>_{LdapM.ChangePassword}
        <form method="post" action="@{toMaster changepassR}">
            <table>
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
                            <input type="hidden" name="regstate" value=state>
                            <input type="submit" value=_{Msg.Register}>
    $of ResetPassword
        <h3>_{LdapM.ChangePassword}
        <form method="post" action="@{toMaster resetpassR}">
            <table>
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
                            <input type="hidden" name="regstate" value=state>
                            <input type="submit" value=_{Msg.Register}>
|]



postPasswordR :: YesodAuthLdap master 
              => SetPasswordState
              -> LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postPasswordR regstate auth bind = do

    
                
    toMaster <- getRouteToMaster
    y <- getYesod
    
    maid <- maybeAuthId
    aid <- case maid of
            Nothing -> do
                setMessageI Msg.BadSetPass
                redirect $ toMaster LoginR
            Just aid -> return aid
    
    case regstate of
        NewUser -> do
            (username, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "username"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                setSession newUserSKey ""
                redirect $ toMaster setpassR
            
            res <- register username new aid auth bind
            case res of
                RegOk        -> return ()
                UsernameUsed -> do
                                setMessageI $ LdapM.RegistrationError UsernameUsed username
                                setSession newUserSKey ""
                                redirect $ toMaster setpassR                    
                e            -> do
                                setMessageI $ LdapM.RegistrationError e username
                                setSession newUserSKey ""
                                redirect $ toMaster LoginR
                            
            
        ChangePassword -> do
            (old, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "old"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster changepassR
            
            -- TODO check old password
            ok <- login aid old auth bind
            
            when (not ok)  $ do
                setMessageI LdapM.WrongOldPassword
                setSession newUserSKey ""
                redirect $ toMaster changepassR
                
            res <- updatePassword aid new auth bind
            
            case res of
                 PassUpdateOk -> return ()
                 e -> do
                     setMessageI $ LdapM.PasswordUpdateError e
                     redirect $ loginDest y -- TODO: where to go
        ResetPassword -> do
            (new, confirm) <- runInputPost $ (,)
                <$> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster resetpassR
            
            res <- updatePassword aid new auth bind
            case res of
                 PassUpdateOk -> return ()
                 e -> do
                     setMessageI $ LdapM.PasswordUpdateError e
                     redirect $ loginDest y -- TODO where to go?
            

    setMessageI Msg.PassUpdated
    redirect $ loginDest y
    
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

instance YesodAuthLdap m => RenderMessage m LdapMessage where
    renderMessage = renderLdapMessage