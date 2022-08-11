/**
 * Copyright (c) 2022, tan2pow16;
 *  all rights reserved.
 *
 * This program extracts bundled ESET quarantine files packaged
 *  by the "export" program in this repo.
 * Do *NOT* run this script outside a properly setup VM! The
 *  extracted files are LIVE MALWARE!
 *
 * I am NOT responsible to any harm done to any of your devices!
 *
 * https://github.com/tan2pow16
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const querystring = require('querystring');

/**
 * 
 * @param {Buffer} buf Data
 * @param {Number} off Offset
 * @returns {Number} LE integer value
 */
function buf2int32(buf, off)
{
  return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24);
}

/**
 * 
 * @param {Buffer} buf NQF data
 * @returns {Buffer} Decoded data
 */
function decodeNQF(buf)
{
  for(let i = 0 ; i < buf.length ; i++)
  {
    buf[i] = (buf[i] - 84) ^ 165;
  }
  return buf;
}

/**
 * 
 * @param {Buffer} buf NDF data
 * @returns {Object} Decoded data
 */
function decodeNDF(buf)
{
  let ret = {};

  let ptr = 64;

  let det_type_len = buf2int32(buf, ptr) * 2;
  ptr += 4;
  ret['det_type'] = buf.slice(ptr, ptr + det_type_len).toString('utf16le');
  ptr += det_type_len;

  let det_type_name_len = buf2int32(buf, ptr) * 2;
  ptr += 4;
  ret['det_type_name'] = buf.slice(ptr, ptr + det_type_name_len).toString('utf16le');
  ptr += det_type_name_len;

  ptr += 12;

  ret['epoch'] = buf2int32(buf, ptr);
  ret['time'] = new Date(ret['epoch'] * 1E3);
  ptr += 4;

  let filename_len = buf2int32(buf, ptr) * 2;
  ptr += 4;
  let fn = buf.slice(ptr, ptr + filename_len).toString('utf16le');
  if(fn.startsWith('mailto:?'))
  {
    let parsed = querystring.parse(fn.substring(8));
    fn = querystring.unescape(parsed['attachment']);
  }
  ret['filename'] = fn;
  ptr += filename_len;

  return ret;
}

/**
 * 
 * @param {String} file_path Input bundled file path
 * @param {String} dir_dest Output base directory
 * @returns {Object} Array of parsed NDF entries in the bundle
 */
function decodeBundleFile(file_path, dir_dest)
{
  if(!fs.existsSync(dir_dest))
  {
    fs.mkdirSync(dir_dest, {recursive: true});
  }

  const sep = path.sep;
  let data_raw = fs.readFileSync(file_path);
  let ptr = 0;
  let ret = [];
  while(ptr < data_raw.length)
  {
    let ndf_hash_name = data_raw.slice(ptr + 1, ptr + data_raw[ptr] + 1).toString('utf8');
    ptr += data_raw[ptr] + 1;
    if(ndf_hash_name.split('.')[1].toLowerCase() !== 'ndf')
    {
      throw new Error(`Invalid NDF entry in "${file_path}" with name "${ndf_hash_name}".`);
    }
    console.log(ndf_hash_name);

    let ndf_gzip_len = buf2int32(data_raw, ptr);
    ptr += 4;
    let ndf_raw = zlib.gunzipSync(data_raw.slice(ptr, ptr + ndf_gzip_len));
    ptr += ndf_gzip_len;
    let ndf_entry = decodeNDF(ndf_raw);

    let entry_dir = `${dir_dest}${sep}${ndf_entry.time.getUTCFullYear()}${sep}${`0${ndf_entry.time.getUTCMonth() + 1}`.slice(-2)}`;
    if(!fs.existsSync(entry_dir))
    {
      fs.mkdirSync(entry_dir, {recursive: true});
    }

    let nqf_hash_name = data_raw.slice(ptr + 1, ptr + data_raw[ptr] + 1).toString('utf8');
    if(nqf_hash_name.split('.')[1].toLowerCase() !== 'nqf')
    {
      throw new Error(`Invalid NQF entry in "${file_path}" with name "${nqf_hash_name}".`);
    }
    ptr += data_raw[ptr] + 1;

    let nqf_gzip_len = buf2int32(data_raw, ptr);
    ptr += 4;
    let nqf_data = zlib.gunzipSync(data_raw.slice(ptr, ptr + nqf_gzip_len));
    ptr += nqf_gzip_len;
    decodeNQF(nqf_data);

    let md5hex = crypto.createHash('md5').update(nqf_data).digest('hex');
    let out_file_path = `${entry_dir}${sep}${md5hex}`;
    fs.writeFileSync(out_file_path, nqf_data);
    fs.utimesSync(out_file_path, ndf_entry.epoch, ndf_entry.epoch);

    ndf_entry['hash'] = md5hex;
    ret.push(ndf_entry);
  }

  return ret;
}

/**
 * 
 * @param {String} dir_src Directory containing the bundled binaries
 * @param {String} dir_dst Destination for storing the decoded malware files
 */
function decodeFolder(dir_src, dir_dst)
{
  if(!fs.existsSync(dir_dst))
  {
    fs.mkdirSync(dir_dst, {recursive: true});
  }

  const sep = path.sep;
  let files = fs.readdirSync(dir_src);
  let ndf_list = {};
  for(let i = 0 ; i < files.length ; i++)
  {
    if(files[i].match(/Nod32MalPack_\d{10}\.bin/g))
    {
      let sub_list = decodeBundleFile(`${dir_src}${sep}${files[i]}`, dir_dst);
      for(let j = 0 ; j < sub_list.length ; j++)
      {
        let yr = `${sub_list[j].time.getUTCFullYear()}`;
        let mon = `0${sub_list[j].time.getMonth() + 1}`.slice(-2);
        if(!ndf_list[yr])
        {
          ndf_list[yr] = {};
        }
        if(!ndf_list[yr][mon])
        {
          ndf_list[yr][mon] = {};
        }
        ndf_list[yr][mon][sub_list[j].hash] = {
          date: `${yr}${mon}${`0${sub_list[j].time.getDate()}`.slice(-2)}`,
          name: sub_list[j].filename
        };
      }
    }
  }

  let years = Object.keys(ndf_list);
  for(let i = 0 ; i < years.length ; i++)
  {
    let months = Object.keys(ndf_list[years[i]]);
    for(let j = 0 ; j < months.length ; j++)
    {
      let json_data = JSON.stringify(ndf_list[years[i]][months[j]], null, 2);
      fs.writeFileSync(`${dir_dst}${sep}${years[i]}${sep}${months[j]}${sep}table.json`, Buffer.from(json_data, 'utf8'));
    }
  }
}

function __main__()
{
  decodeFolder('D:\\workspace\\NQF', 'D:\\malware');
}

__main__();
