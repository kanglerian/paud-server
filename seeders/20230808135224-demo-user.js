'use strict';

const bcrypt = require('bcrypt');

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    const hashedPassword = (password) => {
      return bcrypt.hashSync(password, 10);
    }
    await queryInterface.bulkInsert('Users', [{
      username: "kanglerian",
      email: "kanglerian@gmail.com",
      password: hashedPassword('lerian123'),
      refresh_token: null,
      createdAt: new Date(),
      updatedAt: new Date()
    }], {});
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('Users', null, {});
  }
};
