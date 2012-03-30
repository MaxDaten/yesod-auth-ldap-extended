{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Yesod.Auth.Ldap.Handler.Password 
    (
    -- * routes
      setpassR
    , resetpassR
    , changepassR
    -- * posts/gets
    , getChangePassR
    , postChangePassR
    , postNewUserR
    , getNewUserR
    , postResetPassR
    , getResetPassR
    ) where

--import Yesod
import Yesod.Auth
import Control.Applicative
import Data.Text (Text)
import qualified Data.Text as TS

import Yesod.Message (RenderMessage (..))
import qualified Yesod.Auth.Message as Msg
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

import Control.Monad (when)  

import Text.Blaze (Html, toHtml)

import Yesod.Form
import Yesod.Handler
import Yesod.Widget
import Yesod.Content
import Yesod.Core (whamlet, defaultLayout, setTitleI)
import Control.Monad.IO.Class (liftIO)

import Web.Authenticate.LDAP
import LDAP

import Yesod.Auth.Ldap.YesodAuthLdap

setpassR, changepassR, resetpassR:: AuthRoute

setpassR    = PluginR "ldap" ["set-password"]
resetpassR  = PluginR "ldap" ["reset-password"]
changepassR = PluginR "ldap" ["change-password"]



data Cr = Cr
    { crUsername :: Text
    , crPassword :: Text
    }
    deriving (Show)


getResetPassR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getResetPassR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    
    ((res, widget), enctype) <- runFormPost resetPassForm
    
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{LdapM.ChangePassword}
            <form method="post" action="@{toMaster resetpassR}">
                ^{widget}
                <input type="submit" value=_{Msg.ConfirmPass}>
        |]




postResetPassR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postResetPassR auth bind = do
    aid <- postHandleAuth
        
    toMaster <- getRouteToMaster
    y <- getYesod
    
    
    ((res, widget), enctype) <- runFormPost resetPassForm
    pass <- case res of
        FormSuccess e -> return e
        FormFailure [e] -> do 
                setMessage $ toHtml e
                redirect $ toMaster resetpassR
        _ -> do
                setMessage $ toHtml ("Unbekannter Fehler" :: Text)
                redirect $ loginDest y
    
    res <- updatePassword aid pass auth bind
    case res of
            PassUpdateOk -> return ()
            e -> do
                setMessageI $ LdapM.PasswordUpdateError e
                redirect $ loginDest y -- TODO where to go?
                           

    setMessageI Msg.PassUpdated
    redirect $ loginDest y



getNewUserR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getNewUserR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    
    ((res, widget), enctype) <- runFormPost $  newUserForm
    
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{Msg.Register}
            <form method="post" action="@{toMaster setpassR}">
                ^{widget}
                <input type="submit" value=_{Msg.Register}>
        |]



postNewUserR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master (RepHtml)
postNewUserR auth bind = 
    do
        aid <- postHandleAuth
        
        toMaster <- getRouteToMaster
        y <- getYesod
        
        
        
        ((res, widget), enctype) <- runFormPost newUserForm
        cr <- case res of
            FormSuccess e -> return e
            FormFailure [e] -> do 
                setMessage $ toHtml e
                redirect $ toMaster setpassR
            _ -> do
                setMessage $ toHtml ("Unbekannter Fehler" :: Text)
                redirect $ loginDest y
        
        res <- register (crUsername cr) (crPassword cr) aid auth bind
        case res of
            RegOk        -> return ()
            UsernameUsed -> do
                            setMessageI $ LdapM.RegistrationError UsernameUsed (crUsername cr)
                            redirect $ toMaster setpassR                    
            e            -> do
                            setMessageI $ LdapM.RegistrationError e (crUsername cr)
                            redirect $ toMaster LoginR
        setMessageI Msg.PassUpdated
        redirect $ loginDest y





getChangePassR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getChangePassR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    
    ((res, widget), enctype) <- runFormPost changePassForm
    
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{LdapM.ChangePassword}
            <form method="post" action="@{toMaster changepassR}">
                ^{widget}
                <input type="submit" value=_{Msg.ConfirmPass}>
        |]




postChangePassR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postChangePassR auth bind = 
    do
        aid <- postHandleAuth
        
        toMaster <- getRouteToMaster
        y <- getYesod
        
        ((res, widget), enctype) <- runFormPost changePassForm
        (old,new) <- case res of
            FormSuccess e -> return e
            FormFailure [e] -> do 
                setMessage $ toHtml e
                redirect $ toMaster changepassR
            _ -> do
                setMessage $ toHtml ("Unbekannter Fehler" :: Text)
                redirect $ loginDest y
                
        ok <- login aid old auth bind
        
        when (not ok)  $ do
            setMessageI LdapM.WrongOldPassword
            redirect $ toMaster changepassR
            
        res <- updatePassword aid new auth bind
        
        case res of
                PassUpdateOk -> return ()
                e -> do
                    setMessageI $ LdapM.PasswordUpdateError e
                    redirect $ loginDest y -- TODO: where to go

        setMessageI Msg.PassUpdated
        redirect $ loginDest y




postHandleAuth :: YesodAuthLdap master 
              => GHandler Auth master (AuthId master)
postHandleAuth = do
    toMaster <- getRouteToMaster
    maid <- maybeAuthId
    aid <- case maid of
            Nothing -> do
                setMessageI Msg.BadSetPass
                redirect $ toMaster LoginR
            Just aid -> return aid   
    return aid




getHandleAuth :: YesodAuthLdap master 
           => GHandler Auth master ()
getHandleAuth = do
    toMaster <- getRouteToMaster
    maid <- maybeAuthId
    case maid of
        Just _ -> return ()
        Nothing -> do
            setMessageI Msg.BadSetPass
            redirect $ toMaster LoginR




newUserForm :: YesodAuthLdap m
            => Html -> MForm sub m (FormResult Cr, GWidget sub m ())
newUserForm = renderTable $ Cr
        <$> areq textField (fs LdapM.Username) Nothing
        <*> areq newPasswordFields ("") Nothing
    where 
        fs msg = FieldSettings
            { fsLabel = msg
            , fsTooltip = Nothing
            , fsId = Nothing
            , fsName = Nothing
            , fsClass = []
            }

resetPassForm :: YesodAuthLdap m
            => Html -> MForm sub m (FormResult Text, GWidget sub m ())
resetPassForm = renderTable $ areq newPasswordFields ("") Nothing

  
changePassForm :: YesodAuthLdap m
            => Html -> MForm sub m (FormResult (Text, Text), GWidget sub m ())
changePassForm = renderTable $ (,)
        <$> areq passwordField (fs LdapM.OldPassword) Nothing
        <*> areq newPasswordFields ("") Nothing
    where 
        fs msg = FieldSettings
            { fsLabel = msg
            , fsTooltip = Nothing
            , fsId = Nothing
            , fsName = Nothing
            , fsClass = []
            }
        
newPasswordFields :: YesodAuthLdap master
                     => Field sub master Text
newPasswordFields = Field
    { fieldParse = \rawVals ->
        case rawVals of
            [a, b]
                | a == b -> checkPass a
                | otherwise -> return $ Left "Passwörter stimmen nicht überein" 
            [] -> return $ Right Nothing
            _ -> return $ Left $ "Fehler"
    , fieldView = \idAttr nameAttr _ eResult isReq -> [whamlet|
    Das Passwort muss aus mindestens 6 Zeichen bestehen
<div>
    _{Msg.NewPass}
    <input id=#{idAttr} name=#{nameAttr} type=password required>
<div>
    _{Msg.ConfirmPass}
    <input id=#{idAttr}-confirm name=#{nameAttr} type=password required>
|]
    }
    where checkPass a   | TS.length a < 6 = return $ Left "Das Passwort muss mindestens 6 Zeichen lang sein."
                        | otherwise       = return $ Right $ Just a