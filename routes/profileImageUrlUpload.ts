/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { Request, Response, NextFunction } from 'express'

import { UserModel } from '../models/user'
const utils = require('../lib/utils')
const security = require('../lib/insecurity')
const request = require('request')
const logger = require('../lib/logger')

module.exports = function profileImageUrlUpload () {
  import path = require('path')
  import validUrl = require('valid-url')

  import path = require('path')
  import validUrl = require('valid-url')

  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (validUrl.isUri(url)) {
          const filename = path.basename(url)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(filename.split('.').slice(-1)[0].toLowerCase()) ? filename.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const safePath = path.join('frontend', 'dist', 'frontend', 'assets', 'public', 'images', 'uploads', `${loggedInUser.data.id}.${ext}`)
          const imageRequest = request
            .get(url)
            .on('error', function (err: unknown) {
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
            })
            .on('response', function (res: Response) {
              if (res.statusCode === 200) {
                imageRequest.pipe(fs.createWriteStream(safePath))
                UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
              } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            })
        } else {
          next(new Error('Invalid URL'))
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
