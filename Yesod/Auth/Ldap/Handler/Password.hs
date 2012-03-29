{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
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

import Yesod.Auth
import Control.Applicative
import Data.Text (Text)

import Yesod.Message (RenderMessage (..))
import qualified Yesod.Auth.Message as Msg
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

import Control.Monad (when)  
import Control.Monad.IO.Class (liftIO)

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)

import Web.Authenticate.LDAP
import LDAP

import Yesod.Auth.Ldap.YesodAuthLdap

setpassR, changepassR, resetpassR:: AuthRoute

setpassR    = PluginR "ldap" ["set-password"]
resetpassR  = PluginR "ldap" ["reset-password"]
changepassR = PluginR "ldap" ["change-password"]


    
getResetPassR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getResetPassR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{LdapM.ChangePassword}
                <form method="post" action="@{toMaster resetpassR}">
                    <table>
                        <tr>
                            <th>_{Msg.NewPass}
                            <td>
                                    <input type="password" name="new" required>
                        <tr>
                            <th>_{Msg.ConfirmPass}
                            <td>
                                <input type="password" name="confirm" required>
                        <tr>
                            <td colspan="2">
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
    
    
getNewUserR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getNewUserR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{Msg.Register}
            <form method="post" action="@{toMaster setpassR}">
                <table>
                    <tr>
                        <th>_{LdapM.Username}
                        <td>
                            <input type="text" name="username" required>
                    <tr>
                        <th>_{Msg.NewPass}
                        <td>
                                <input type="password" name="new" required>
                    <tr>
                        <th>_{Msg.ConfirmPass}
                        <td>
                            <input type="password" name="confirm" required>
                    <tr>
                        <td colspan="2">
                                <input type="submit" value=_{Msg.Register}>
        |]


postNewUserR :: YesodAuthLdap master 
              => LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postNewUserR auth bind = 
    do
        aid <- postHandleAuth
        
        toMaster <- getRouteToMaster
        y <- getYesod
        
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
                            setMessageI $ LdapM.RegistrationError UsernameUsed username
                            redirect $ toMaster setpassR                    
            e            -> do
                            setMessageI $ LdapM.RegistrationError e username
                            redirect $ toMaster LoginR
        setMessageI Msg.PassUpdated
        redirect $ loginDest y



getChangePassR :: YesodAuthLdap master 
               => GHandler Auth master RepHtml
getChangePassR = do
    getHandleAuth
    
    toMaster <- getRouteToMaster
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
            <h3>_{LdapM.ChangePassword}
            <form method="post" action="@{toMaster changepassR}">
                <table>
                    <tr>
                        <th>_{LdapM.OldPassword}
                        <td>
                            <input type="password" name="old" required>
                    <tr>
                        <th>_{Msg.NewPass}
                        <td>
                                <input type="password" name="new" required>
                    <tr>
                        <th>_{Msg.ConfirmPass}
                        <td>
                            <input type="password" name="confirm" required>
                    <tr>
                        <td colspan="2">
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


passwordConfirmField :: Field sub master Text
passwordConfirmField = Field
    { fieldParse = \rawVals ->
        case rawVals of
            [a, b]
                | a == b -> return $ Right $ Just a
                | otherwise -> return $ Left "Passwords don't match"
            [] -> return $ Right Nothing
            _ -> return $ Left "You must enter two values"
    , fieldView = \idAttr nameAttr _ eResult isReq -> [whamlet|
<input id=#{idAttr} name=#{nameAttr} type=password>
<div>Confirm:
<input id=#{idAttr}-confirm name=#{nameAttr} type=password>
|]
    }