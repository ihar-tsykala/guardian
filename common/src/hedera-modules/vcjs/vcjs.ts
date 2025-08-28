import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { ld as vcjs } from '@transmute/vc.js';
import { Ed25519Signature2018, Ed25519VerificationKey2018 } from '@transmute/ed25519-signature-2018';
import { PrivateKey } from '@hashgraph/sdk';
import { CheckResult } from '@transmute/jsonld-schema';
import { GenerateUUIDv4, ICredentialSubject, IVC, SignatureType } from '@guardian/interfaces';
import { VcDocument } from './vc-document.js';
import { VpDocument } from './vp-document.js';
import { VcSubject } from './vc-subject.js';
import { TimestampUtils } from '../timestamp-utils.js';
import { DocumentLoaderFunction } from '../document-loader/document-loader-function.js';
import { DocumentLoader } from '../document-loader/document-loader.js';
import { SchemaLoader, SchemaLoaderFunction } from '../document-loader/schema-loader.js';
import { Issuer } from './issuer.js';
import axios from 'axios';
import { BbsBlsSignature2020, BbsBlsSignatureProof2020, Bls12381G2KeyPair, KeyPairOptions } from '@mattrglobal/jsonld-signatures-bbs';
import { IPFS } from '../../helpers/index.js';
import { CommonDidDocument, HederaBBSMethod, HederaDidDocument, HederaEd25519Method } from './did/index.js';
import { BBSDidRootKey, DidRootKey } from './did-document.js';

import * as pkg from 'jsonld-signatures';
import { ContextHelper } from './context-helper.js';
const { verify, purposes } = pkg;

/**
 * Suite interface
 */
export interface ISuite {
    /**
     * Issuer
     */
    issuer: string;
    /**
     * Suite
     */
    suite: Ed25519Signature2018;
}

/**
 * Suite options
 */
export interface ISuiteOptions {
    /**
     * Issuer
     */
    did: string;
    /**
     * Private key
     */
    key: string | PrivateKey,
    /**
     * Signature type
     */
    signatureType?: SignatureType;
}

/**
 * Document options
 */
export interface IDocumentOptions {
    /**
     * Group
     */
    group?: {
        /**
         * Group ID
         */
        groupId: string;
        /**
         * Group type
         */
        type: string;
        /**
         * Group context
         */
        context: any;
    };
    /**
     * UUID
     */
    uuid?: string;
}

/**
 * Connecting VCJS library
 */
export class VCJS {
    /**
     * Document loaders
     * @private
     */
    private readonly documentLoaders: DocumentLoader[];
    /**
     * Schema loaders
     * @private
     */
    private readonly schemaLoaders: SchemaLoader[];
    /**
     * Schema context
     * @private
     */
    private readonly schemaContext: string[];
    /**
     * Loader
     * @private
     */
    protected loader: DocumentLoaderFunction;
    /**
     * Schema loader
     * @private
     */
    private schemaLoader: SchemaLoaderFunction;

    constructor() {
        this.schemaContext = [];
        this.documentLoaders = [];
        this.schemaLoaders = [];
    }

    /**
     * Add Schema context
     *
     * @param {string} context - context
     *
     */
    public addContext(context: string): void {
        this.schemaContext.push(context);
    }

    /**
     * Add DID or Schema document loader
     *
     * @param {DocumentLoader} documentLoader - Document Loader
     *
     */
    public addDocumentLoader(documentLoader: DocumentLoader): void {
        this.documentLoaders.push(documentLoader);
    }

    /**
     * Build Document Loader
     * Builded loader is used to sign and verify documents
     */
    public buildDocumentLoader(): void {
        this.loader = DocumentLoader.build(this.documentLoaders);
    }

    /**
     * Add Schema loader
     *
     * @param {DocumentLoader} documentLoader - Document Loader
     *
     */
    public addSchemaLoader(schemaLoader: SchemaLoader): void {
        this.schemaLoaders.push(schemaLoader);
    }

    /**
     * Build Schema Loader
     * Builded loader is used to sign and verify documents
     */
    public buildSchemaLoader(): void {
        this.schemaLoader = SchemaLoader.build(this.schemaLoaders);
    }

    /**
     * Generate new UUIDv4
     *
     * @param {IDocumentOptions} documentOptions - Document Options
     */
    protected generateUUID(documentOptions?: IDocumentOptions): string {
        if (documentOptions && documentOptions.uuid) {
            return documentOptions.uuid;
        } else {
            return `urn:uuid:${GenerateUUIDv4()}`;
        }
    }

    /**
     * Verify VC Document
     *
     * @param {any} json - VC Document
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {boolean} - status
     */
    public async verify(json: any, documentLoader: DocumentLoaderFunction): Promise<boolean> {
        let result;
        if (json.proof.type === SignatureType.Ed25519Signature2018) {
            result = await vcjs.verifyVerifiableCredential({
                credential: json,
                suite: [new Ed25519Signature2018()],
                documentLoader,
            });
        } else {
            result = await verify(json, {
                purpose: new purposes.AssertionProofPurpose(),
                suite: [new BbsBlsSignature2020(), new BbsBlsSignatureProof2020()],
                documentLoader,
            });
        }
        if (result.verified) {
            return true;
        } else {
            if (result.results) {
                for (const element of result.results) {
                    if (!element.verified && element.error && element.error.message) {
                        throw new Error(element.error.message);
                    }
                }
            }
            throw new Error('Verification error');
        }
    }

    /**
     * Verify Schema
     *
     * @param {HcsVcDocument<VcSubject>} vcDocument - VC Document
     *
     * @returns {CheckResult} - is verified
     */
    public async verifySchema(vcDocument: VcDocument | any): Promise<CheckResult> {
        let vc: IVC;
        if (vcDocument && typeof vcDocument.toJsonTree === 'function') {
            vc = vcDocument.toJsonTree();
        } else {
            vc = vcDocument;
        }

        if (!vc.credentialSubject) {
            throw new Error('"credentialSubject" property is required.');
        }

        const subjects = vc.credentialSubject;
        const subject = Array.isArray(subjects) ? subjects[0] : subjects;

        if (!this.schemaLoader) {
            throw new Error('Schema Loader not found');
        }

        const schema = await this.schemaLoader(subject['@context'], subject.type, 'vc');

        if (!schema) {
            throw new Error('Schema not found');
        }

        const ajv = new Ajv({
            loadSchema: this.loadSchema
        });
        addFormats(ajv);

        this.prepareSchema(schema);

        console.log(await this.loadSchema, 'await this.loadSchema verifySchema');
        console.log(ajv, 'ajv verifySchema');
        console.log(schema, 'schema verifySchema');

        const validate = await ajv.compileAsync(schema);
        const valid = validate(vc);
        console.log(valid, 'valid verifySchema');
        console.log(validate, 'validate verifySchema');
        console.log(vc, 'vc verifySchema');

        return new CheckResult(valid, 'JSON_SCHEMA_VALIDATION_ERROR', validate.errors as any);
    }

    /**
     * Verify VC Document
     *
     * @param {HcsVcDocument<VcSubject>} vcDocument - VC Document
     *
     * @param loader
     * @returns {Promise<boolean>} - is verified
     */
    public async verifyVC(vcDocument: VcDocument | any, loader?: DocumentLoaderFunction): Promise<boolean> {
        let vc: IVC;
        if (vcDocument && typeof vcDocument.toJsonTree === 'function') {
            vc = vcDocument.toJsonTree();
        } else {
            vc = vcDocument;
        }
        if (!loader) {
            return await this.verify(vc, this.loader);
        } else {
            return await this.verify(vc, loader)
        }
    }

    /**
     * Delete system fields from schema defs
     *
     * @param schema Schema
     */
    private prepareSchema(schema: any) {
        const defsObj = schema.$defs;
        if (!defsObj) {
            return;
        }

        const defsKeys = Object.keys(defsObj);
        for (const key of defsKeys) {
            const nestedSchema = defsObj[key];
            const required = nestedSchema.required;
            if (!required || required.length === 0) {
                continue;
            }
            nestedSchema.required = required.filter((field: any) => !nestedSchema.properties[field] || !nestedSchema.properties[field].readOnly);
        }
    }

    /**
     * Verify Subject
     *
     * @param {any} subject - subject
     *
     * @returns {CheckResult} - is verified
     */
    public async verifySubject(subject: any): Promise<CheckResult> {
        if (!this.schemaLoader) {
            throw new Error('Schema Loader not found');
        }

        const schema = await this.schemaLoader(subject['@context'], subject.type, 'subject');

        if (!schema) {
            throw new Error('Schema not found');
        }

        const ajv = new Ajv({
            loadSchema: this.loadSchema
        });
        addFormats(ajv);

        this.prepareSchema(schema);


        // if (schema.properties) {
        //     Object.entries(schema.properties).forEach(([key, value]: [string, any]) => {
        //         if (value?.$ref) {

        //         }
        //     })
        // }
        // if (subject?.field2?.field11) {
        //     subject.field2.field11.test1 = 'qwe'
        // }
        // if (schema?.$defs?.['#2ebbead8-6fcf-4b52-9435-74f9d5ee81fa']?.properties?.field11) {
        //     schema.$defs['#2ebbead8-6fcf-4b52-9435-74f9d5ee81fa'].properties.field11.test1 = 'qwe';
        // }
        console.log(await this.loadSchema, 'await this.loadSchema verifySubject');
        // console.log(ajv, 'ajv verifySubject');
        console.log(schema, 'schema verifySubject');
        console.log(schema?.$defs?.['#GeoJSON'], 'schema geo verifySubject');
        console.log(schema?.$defs?.['#2ebbead8-6fcf-4b52-9435-74f9d5ee81fa'], 'schema by id verifySubject');


        const validate = await ajv.compileAsync(schema);


        const valid = validate(subject);



        console.log(valid, 'valid verifySubject');
        console.log(validate, 'validate verifySubject');
        console.log(subject, 'subject verifySubject');
        console.log(subject?.field2?.field11, 'subject verifySubject');

function collectGeoJSONPaths(schema) {
  const defs = schema.$defs || {};
  const out = {};

  const parseComment = (c) => {
    if (typeof c !== 'string') return null;
    try { return JSON.parse(c); } catch { return c; }
  };

  const resolveRef = (ref) => {
    if (!ref) return null;
    return defs[ref] || defs[ref.replace(/^#/, '')] || null;
  };

  const visit = (node, path) => {
    if (!node || typeof node !== 'object') return;

    if ('$ref' in node) {
      const ref = node['$ref'];

      if (ref === '#GeoJSON') {
        out[path] = parseComment(node['$comment']);
        return;
      }
      const target = resolveRef(ref);
      if (target) {
        if (target.properties && typeof target.properties === 'object') {
          for (const [k, v] of Object.entries(target.properties)) {
            visit(v, path ? `${path}.${k}` : k);
          }
        }
        for (const comb of ['oneOf', 'allOf', 'anyOf']) {
          if (Array.isArray(target[comb])) target[comb].forEach((sub) => visit(sub, path));
        }
      }
    }

    if (node.properties && typeof node.properties === 'object') {
      for (const [k, v] of Object.entries(node.properties)) {
        visit(v, path ? `${path}.${k}` : k);
      }
    }
    for (const comb of ['oneOf', 'allOf', 'anyOf']) {
      if (Array.isArray(node[comb])) node[comb].forEach((sub) => visit(sub, path));
    }
  };

  if (schema.properties && typeof schema.properties === 'object') {
    for (const [k, v] of Object.entries(schema.properties)) visit(v, k);
  }
  return out;
}

function getByPath(obj, path) {
  return path.split('.').reduce((acc, key) => (acc != null ? acc[key] : undefined), obj);
}

// ===== валидатор GeoJSON с поддержкой Feature/FeatureCollection =====
const SUPPORTED_TYPES = new Set([
  'Point', 'LineString', 'Polygon',
  'MultiPoint', 'MultiLineString', 'MultiPolygon'
]);
const EPS = 1e-9;
const isNumber = (x) => typeof x === 'number' && Number.isFinite(x);

function positionsEqual(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (!isNumber(a[i]) || !isNumber(b[i])) return false;
    if (Math.abs(a[i] - b[i]) > EPS) return false;
  }
  return true;
}

function validatePosition(p, errors, path = 'coordinates') {
  if (!Array.isArray(p)) { errors.push(`${path}: позиция должна быть массивом`); return; }
  if (p.length < 2) { errors.push(`${path}: минимум 2 числа [lon, lat]`); return; }
  const [lon, lat] = p;
  if (!isNumber(lon) || !isNumber(lat)) errors.push(`${path}: lon/lat должны быть числами`);
  if (isNumber(lon) && (lon < -180 || lon > 180)) errors.push(`${path}: lon вне диапазона [-180,180]`);
  if (isNumber(lat) && (lat < -90 || lat > 90)) errors.push(`${path}: lat вне диапазона [-90,90]`);
}

function validateLineString(coords, errors, path) {
  if (!Array.isArray(coords)) { errors.push(`${path}: должен быть массивом позиций`); return; }
  if (coords.length < 2) errors.push(`${path}: минимум 2 позиции`);
  coords.forEach((pos, i) => validatePosition(pos, errors, `${path}[${i}]`));
}

function validateLinearRing(ring, errors, path) {
  if (!Array.isArray(ring)) { errors.push(`${path}: должен быть массивом позиций (кольцо)`); return; }
  if (ring.length < 4) errors.push(`${path}: кольцо минимум 4 позиции`);
  ring.forEach((pos, i) => validatePosition(pos, errors, `${path}[${i}]`));
  if (ring.length >= 4 && !positionsEqual(ring[0], ring[ring.length - 1])) {
    errors.push(`${path}: первое и последнее положение должны совпадать (замкнуто)`);
  }
}

function validatePolygon(coords, errors, path) {
  if (!Array.isArray(coords) || coords.length === 0) {
    errors.push(`${path}: непустой массив колец`);
    return;
  }
  coords.forEach((ring, i) => validateLinearRing(ring, errors, `${path}[${i}]`));
}

function validateGeometry(geom, allowedTypes /* Set|null */, pathBase = '') {
  const errors = [];
  if (geom == null || typeof geom !== 'object' || Array.isArray(geom)) {
    return { ok: false, type: undefined, errors: [`${pathBase||'value'}: должно быть объектом GeoJSON`] };
  }

  const type = geom.type;
  if (typeof type !== 'string') errors.push(`поле "type" обязательно и должно быть строкой`);

  // фильтр по доступным типам
  if (typeof type === 'string' && allowedTypes && allowedTypes.size > 0 && !allowedTypes.has(type)) {
    errors.push(`тип "${type}" не входит в допустимые: [${[...allowedTypes].join(', ')}]`);
  }

  // поддерживаем только перечисленные геометрии
  if (typeof type === 'string' && !SUPPORTED_TYPES.has(type)) {
    errors.push(`тип "${type}" не поддерживается как геометрия (поддерживаются: ${[...SUPPORTED_TYPES].join(', ')})`);
    return { ok: errors.length === 0, type, errors };
  }

  if (!('coordinates' in geom)) {
    errors.push(`отсутствует поле "coordinates"`);
    return { ok: errors.length === 0, type, errors };
  }

  const c = geom.coordinates;

  switch (type) {
    case 'Point':
      validatePosition(c, errors, `${pathBase ? pathBase + '.' : ''}coordinates`);
      break;

    case 'MultiPoint':
      if (!Array.isArray(c)) { errors.push('coordinates: должен быть массивом позиций'); break; }
      if (c.length === 0) errors.push('coordinates: MultiPoint не должен быть пустым');
      c.forEach((pos, i) => validatePosition(pos, errors, `coordinates[${i}]`));
      break;

    case 'LineString':
      validateLineString(c, errors, 'coordinates');
      break;

    case 'MultiLineString':
      if (!Array.isArray(c)) { errors.push('coordinates: должен быть массивом LineString'); break; }
      if (c.length === 0) errors.push('coordinates: MultiLineString не должен быть пустым');
      c.forEach((ls, i) => validateLineString(ls, errors, `coordinates[${i}]`));
      break;

    case 'Polygon':
      validatePolygon(c, errors, 'coordinates');
      break;

    case 'MultiPolygon':
      if (!Array.isArray(c)) { errors.push('coordinates: должен быть массивом Polygon'); break; }
      if (c.length === 0) errors.push('coordinates: MultiPolygon не должен быть пустым');
      c.forEach((poly, i) => validatePolygon(poly, errors, `coordinates[${i}]`));
      break;
  }

  return { ok: errors.length === 0, type, errors };
}

// нормализация availableOptions -> Set поддерживаемых типов (или null = без ограничения)
function normalizeAllowedOptions(meta) {
  const raw = meta && Array.isArray(meta.availableOptions) ? meta.availableOptions : null;
  if (!raw || raw.length === 0) return null;
  const mapByLower = {};
  [...SUPPORTED_TYPES].forEach(t => mapByLower[t.toLowerCase()] = t);
  const set = new Set();
  raw.forEach((x) => {
    if (typeof x !== 'string') return;
    const m = mapByLower[String(x).toLowerCase()];
    if (m) set.add(m);
  });
  return set;
}

// новые: валидаторы Feature и FeatureCollection
function validateFeature(feature, allowedTypes, basePath) {
  const errs = [];
  if (!feature || typeof feature !== 'object' || Array.isArray(feature)) {
    return [{ path: basePath, ok: false, type: 'Feature', errors: ['Feature должен быть объектом'] }];
  }
  if (feature.type !== 'Feature') {
    return [{ path: basePath, ok: false, type: feature.type, errors: ['ожидался type="Feature"'] }];
  }
  const results = [];
  if (!('geometry' in feature)) {
    results.push({ path: basePath, ok: false, type: 'Feature', errors: ['отсутствует поле "geometry"'] });
    return results;
  }
  const g = feature.geometry;
  if (g == null) {
    results.push({ path: basePath + '.geometry', ok: false, type: undefined, errors: ['geometry не может быть null'] });
    return results;
  }
  const r = validateGeometry(g, allowedTypes, basePath + '.geometry');
  results.push({ path: basePath + '.geometry', ...r, allowedTypes: allowedTypes ? [...allowedTypes] : 'не ограничено' });
  return results;
}

function validateFeatureCollection(fc, allowedTypes, basePath) {
  if (!fc || typeof fc !== 'object' || Array.isArray(fc)) {
    return [{ path: basePath, ok: false, type: 'FeatureCollection', errors: ['FeatureCollection должен быть объектом'] }];
  }
  if (fc.type !== 'FeatureCollection') {
    return [{ path: basePath, ok: false, type: fc.type, errors: ['ожидался type="FeatureCollection"'] }];
  }
  if (!Array.isArray(fc.features)) {
    return [{ path: basePath, ok: false, type: 'FeatureCollection', errors: ['поле "features" должно быть массивом'] }];
  }
  // допустим пустой массив — это валидный GeoJSON, просто без фич
  const results = [];
  fc.features.forEach((feat, i) => {
    const sub = validateFeature(feat, allowedTypes, `${basePath}.features[${i}]`);
    results.push(...sub);
  });
  // если коллекция пустая, добавим информационную запись (не ошибка)
  if (fc.features.length === 0) {
    results.push({ path: basePath, ok: true, type: 'FeatureCollection', errors: [] });
  }
  return results;
}

// диспетчер по типу входного значения на пути
function validateAnyGeoValue(value, allowedTypes, basePath) {
  if (value && typeof value === 'object') {
    if (value.type === 'FeatureCollection') {
      return validateFeatureCollection(value, allowedTypes, basePath);
    }
    if (value.type === 'Feature') {
      return validateFeature(value, allowedTypes, basePath);
    }
    // предполагаем «голую» геометрию
    const r = validateGeometry(value, allowedTypes, basePath);
    return [{ path: basePath, ...r, allowedTypes: allowedTypes ? [...allowedTypes] : 'не ограничено' }];
  }
  return [{ path: basePath, ok: false, type: undefined, errors: ['значение должно быть объектом GeoJSON/Feature/FeatureCollection'] }];
}

// ===== связка с обходом схемы =====
function validateDataBySchemaGeoJSON(schema, data) {
  const pathsMeta = collectGeoJSONPaths(schema);
  const all = [];

  for (const [path, meta] of Object.entries(pathsMeta)) {
    const value = getByPath(data, path);
    const allowed = normalizeAllowedOptions(meta);
    console.log(value, 'value');
    console.log(value?.features, 'value.features');
    console.log(value?.features?.[0], 'value.features[0]');
    console.log(value?.features?.[0]?.geometry?.coordinates, 'value.features[0]?.geometry?.coordinates');

    if (value === undefined) {
      all.push({ path, ok: false, type: undefined, errors: ['значение по пути отсутствует'] });
      continue;
    }
    const results = validateAnyGeoValue(value, allowed, path);
    // если allowed есть, но ни один поддерживаемый тип из него не попал — отметим
    if (allowed && allowed.size === 0) {
      results.unshift({ path, ok: false, type: undefined, errors: ['в availableOptions нет поддерживаемых типов (Point/LineString/Polygon/Multi*)'] });
    }
    all.push(...results);
  }

  return all;
}

// ===== пример использования =====
const report = validateDataBySchemaGeoJSON(schema, subject);

// краткий вывод
for (const r of report) {
  if (r.ok) {
    console.log(`[OK] ${r.path} :: ${r.type ?? '—'} :: allowed=${Array.isArray(r.allowedTypes)? r.allowedTypes.join(', ') : (r.allowedTypes ?? '')}`);
  } else {
    console.warn(`[ERR] ${r.path} :: ${r.type ?? '—'}`);
    r.errors.forEach(e => console.warn('  -', e));
  }
}

throw new Error('test');
        return new CheckResult(valid, 'JSON_SCHEMA_VALIDATION_ERROR', validate.errors as any);
    }

    /**
     * Add Context
     *
     * @param {any} subject - subject
     * @param {any} context - new context
     * @returns {any} - subject
     */
    public addContextInSubject(subject: any, context: string): any {
        if (subject['@context']) {
            if (Array.isArray(subject['@context'])) {
                subject['@context'].push(context);
            } else {
                subject['@context'] = [subject['@context'], context];
            }
        } else {
            subject['@context'] = [context];
        }
        return subject
    }

    /**
     * Add Context
     *
     * @param {any} subject - subject
     * @returns {any} - subject
     */
    public addDryRunContext(subject: any, context?: string[]): any {
        if (!subject || typeof subject !== 'object') {
            return subject;
        }

        if (Array.isArray(subject)) {
            for (const subjectItem of subject) {
                this.addDryRunContext(subjectItem, context);
            }
            return subject;
        }

        if (!subject.type) {
            return subject;
        }

        subject['@context'] = context || [`schema:${subject.type}`];

        for (const value of Object.values(subject)) {
            this.addDryRunContext(value, subject['@context']);
        }

        return subject;
    }

    /**
     * Load schema by URI
     * @param uri URI
     * @returns Schema
     */
    public async loadSchema(uri: string) {
        try {
            let response: any;
            if (uri.startsWith(IPFS.IPFS_PROTOCOL)) {
                const cidMatches = uri.match(IPFS.CID_PATTERN);
                response = JSON.parse(
                    Buffer.from(
                        await IPFS.getFile(
                            (cidMatches && cidMatches[0]) || '',
                            'raw'
                        )
                    ).toString()
                );
            } else {
                response = (await axios.get(uri)).data;
            }
            return response;
        } catch (err) {
            throw new Error('Can not resolve reference: ' + uri);
        }
    }

    /**
     * Create Ed25519 Suite by DID
     *
     * @param {any} verificationMethod - Verification Method
     *
     * @returns {Ed25519Signature2018} - Ed25519Signature2018
     */
    public async createEd25519Suite(verificationMethod: KeyPairOptions): Promise<Ed25519Signature2018> {
        const key = await Ed25519VerificationKey2018.from(verificationMethod);
        return new Ed25519Signature2018({ key });
    }

    /**
     * Create BBS Suite by DID
     *
     * @param {any} verificationMethod - Verification Method
     *
     * @returns {BbsBlsSignature2020} - BbsBlsSignature2020
     */
    public async createBBSSuite(verificationMethod: KeyPairOptions): Promise<BbsBlsSignature2020> {
        const key = await Bls12381G2KeyPair.from(verificationMethod);
        return new BbsBlsSignature2020({ key });
    }

    /**
     * Issue VC Document
     *
     * @param {HcsVcDocument<T>} vcDocument - VC Document
     * @param {Ed25519Signature2018} suite - suite
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {HcsVcDocument<T>} - VC Document
     */
    public async issue(
        vcDocument: VcDocument,
        suite: Ed25519Signature2018 | BbsBlsSignature2020,
        documentLoader: DocumentLoaderFunction
    ): Promise<VcDocument> {
        const vc: any = vcDocument.getDocument();
        ContextHelper.clearContext(vc);
        const verifiableCredential = await vcjs.createVerifiableCredential({
            credential: vc,
            suite,
            documentLoader,
        });
        if (
            suite instanceof BbsBlsSignature2020 &&
            verifiableCredential.proof?.type
        ) {
            verifiableCredential.proof.type = SignatureType.BbsBlsSignature2020;
        }
        vcDocument.proofFromJson(verifiableCredential);
        return vcDocument;
    }

    /**
     * Issue VP Document
     *
     * @param {HcsVpDocument} vpDocument - VP Document
     * @param {Ed25519Signature2018} suite - suite
     * @param {DocumentLoaderFunction} documentLoader - Document Loader
     *
     * @returns {HcsVpDocument} - VP Document
     */
    public async issuePresentation(
        vpDocument: VpDocument,
        suite: Ed25519Signature2018,
        documentLoader: DocumentLoaderFunction
    ): Promise<VpDocument> {
        const vp = vpDocument.toJsonTree();
        const verifiablePresentation = await vcjs.createVerifiablePresentation({
            presentation: vp,
            challenge: '123',
            suite,
            documentLoader,
        });
        vpDocument.proofFromJson(verifiablePresentation);
        return vpDocument;
    }

    /**
     * Create Suite by DID
     *
     * @param {DidRootKey} document - DID document
     *
     * @returns {Ed25519Signature2018} - Ed25519Signature2018
     *
     * @deprecated 2024-02-12
     */
    public async createSuite(document: DidRootKey | BBSDidRootKey): Promise<Ed25519Signature2018 | BbsBlsSignature2020> {
        const verificationMethod: any = document.getPrivateVerificationMethod();
        switch (verificationMethod.type) {
            case BBSDidRootKey.DID_ROOT_KEY_TYPE:
                return this.createBBSSuite(verificationMethod);
            default:
                return this.createEd25519Suite(verificationMethod);
        }
    }

    /**
     * Create Suite by Method
     *
     * @param {SignatureType} type - Signature type
     *
     * @returns {Ed25519Signature2018 | BbsBlsSignature2020} - Ed25519Signature2018 | BbsBlsSignature2020
     */
    public async createSuiteByMethod(
        didDocument: CommonDidDocument,
        type: SignatureType
    ): Promise<Ed25519Signature2018 | BbsBlsSignature2020> {
        switch (type) {
            case SignatureType.BbsBlsSignature2020: {
                const verificationMethod = didDocument.getMethodByType(HederaBBSMethod.TYPE);
                if (!verificationMethod) {
                    throw new Error('Verification method not found.');
                }
                if (!verificationMethod.hasPrivateKey()) {
                    throw new Error('Private key not found.');
                }
                const option: any = verificationMethod.toObject(true);
                return this.createBBSSuite(option);
            }
            default: {
                const verificationMethod = didDocument.getMethodByType(HederaEd25519Method.TYPE);
                if (!verificationMethod) {
                    throw new Error('Verification method not found.');
                }
                if (!verificationMethod.hasPrivateKey()) {
                    throw new Error('Private key not found.');
                }
                const option: any = verificationMethod.toObject(true);
                return this.createEd25519Suite(option);
            }
        }
    }

    /**
     * Generate verification method by Hedera key
     *
     * @param {ISuiteOptions} suiteOptions - Suite Options (DID, Private Key, Signature Type)
     *
     * @returns {HederaDidDocument} - DID Document
     */
    public async generateDid(suiteOptions: ISuiteOptions): Promise<HederaDidDocument> {
        return await HederaDidDocument.generateByDid(suiteOptions.did, suiteOptions.key);
    }

    /**
     * Create VC Document
     *
     * @param {string} did - DID
     * @param {PrivateKey | string} key - Private Key
     * @param {any} subject - Credential Object
     * @param {any} [group] - Issuer
     *
     * @returns {VcDocument} - VC Document
     *
     * @deprecated 2024-02-12
     */
    public async createVC(
        did: string,
        key: string | PrivateKey,
        subject: ICredentialSubject,
        group?: any,
        signatureType: SignatureType = SignatureType.Ed25519Signature2018,
    ): Promise<VcDocument> {
        const didDocument = await this.generateDid({ did, key, signatureType });
        return await this.createVerifiableCredential(subject, didDocument, signatureType, { group });
    }

    /**
     * Create VC Document
     *
     * @param {string} did - DID
     * @param {PrivateKey | string} key - Private Key
     * @param {VcDocument} vc - json
     *
     * @returns {VcDocument} - VC Document
     *
     * @deprecated 2024-02-12
     */
    public async issueVC(
        did: string,
        key: string | PrivateKey,
        vc: VcDocument
    ): Promise<VcDocument> {
        const didDocument = await this.generateDid({ did, key });
        const signatureType = vc.getSignatureType();
        return await this.issueVerifiableCredential(vc, didDocument, signatureType);
    }

    /**
     * Create VC Document
     *
     * @param {ICredentialSubject} subject - Credential Object
     * @param {ISuiteOptions} suiteOptions - Suite Options (Issuer, Private Key, Signature Type)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     *
     * @deprecated 2024-02-12
     */
    public async createVcDocument(
        subject: ICredentialSubject,
        suiteOptions: ISuiteOptions,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const didDocument = await this.generateDid(suiteOptions);
        const signatureType = suiteOptions.signatureType || SignatureType.Ed25519Signature2018;
        return await this.createVerifiableCredential(subject, didDocument, signatureType, documentOptions);
    }

    /**
     * Create VC Document
     *
     * @param {VcDocument} vc - VC Document
     * @param {ISuiteOptions} suiteOptions - Suite Options (Issuer, Private Key)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     *
     * @deprecated 2024-02-12
     */
    public async issueVcDocument(
        vc: VcDocument,
        suiteOptions: ISuiteOptions,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const didDocument = await this.generateDid(suiteOptions);
        const signatureType = vc.getSignatureType();
        return await this.issueVerifiableCredential(vc, didDocument, signatureType, documentOptions);
    }

    /**
     * Create VC Document
     *
     * @param {ICredentialSubject} subject - Credential Object
     * @param {CommonDidDocument} didDocument - DID Document
     * @param {SignatureType} signatureType - Signature type (Ed25519Signature2018, BbsBlsSignature2020)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     */
    public async createVerifiableCredential(
        subject: ICredentialSubject,
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const vcSubject = VcSubject.create(subject);
        const vc = new VcDocument(signatureType);
        vc.addCredentialSubject(vcSubject);
        vc.addContexts(subject['@context']);
        vc.addContexts(this.schemaContext);
        if (documentOptions && documentOptions.group) {
            vc.setIssuer(new Issuer(didDocument.getDid(), documentOptions.group.groupId));
            vc.addType(documentOptions.group.type);
            vc.addContext(documentOptions.group.context);
        } else {
            vc.setIssuer(new Issuer(didDocument.getDid()));
        }
        return await this.issueVerifiableCredential(vc, didDocument, signatureType, documentOptions);
    }

    /**
     * Create VC Document
     *
     * @param {VcDocument} verifiableCredential - VC Document
     * @param {CommonDidDocument} didDocument - DID Document
     * @param {SignatureType} signatureType - Signature type (Ed25519Signature2018, BbsBlsSignature2020)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VcDocument} - VC Document
     */
    public async issueVerifiableCredential(
        verifiableCredential: VcDocument,
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VcDocument> {
        const id = this.generateUUID(documentOptions);
        const suite = await this.createSuiteByMethod(didDocument, signatureType);
        verifiableCredential.setId(id);
        verifiableCredential.setIssuanceDate(TimestampUtils.now());
        verifiableCredential.setProof(null);
        return await this.issue(verifiableCredential, suite, this.loader);
    }

    /**
     * Create VP Document
     *
     * @param {string} did - DID
     * @param {PrivateKey | string} key - Private Key
     * @param {VcDocument[]} vcs - VC Documents
     * @param {string} [uuid] - new uuid
     *
     * @returns {VpDocument} - VP Document
     *
     * @deprecated 2024-02-12
     */
    public async createVP(
        did: string,
        key: string | PrivateKey,
        vcs: VcDocument[],
        uuid?: string
    ): Promise<VpDocument> {
        const didDocument = await this.generateDid({ did, key });
        return await this.createVerifiablePresentation(vcs, didDocument, SignatureType.Ed25519Signature2018, { uuid });
    }

    /**
     * Create VP Document
     *
     * @param {VcDocument[]} vcs - VC Documents
     * @param {ISuiteOptions} suiteOptions - Suite Options (Issuer, Private Key)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VpDocument} - VP Document
     *
     * @deprecated 2024-02-12
     */
    public async createVpDocument(
        vcs: VcDocument[],
        suiteOptions: ISuiteOptions,
        documentOptions?: IDocumentOptions
    ): Promise<VpDocument> {
        const didDocument = await this.generateDid(suiteOptions);
        return await this.createVerifiablePresentation(vcs, didDocument, SignatureType.Ed25519Signature2018, documentOptions);
    }

    /**
     * Create VP Document
     *
     * @param {VcDocument[]} vcs - VC Documents
     * @param {ISuiteOptions} suiteOptions - Suite Options (Issuer, Private Key)
     * @param {IDocumentOptions} [documentOptions] - Document Options (UUID, Group)
     *
     * @returns {VpDocument} - VP Document
     */
    public async createVerifiablePresentation(
        vcs: VcDocument[],
        didDocument: CommonDidDocument,
        signatureType: SignatureType,
        documentOptions?: IDocumentOptions
    ): Promise<VpDocument> {
        const id: string = this.generateUUID(documentOptions);
        const suite = await this.createSuiteByMethod(didDocument, SignatureType.Ed25519Signature2018) as Ed25519Signature2018;
        const vp = new VpDocument();
        vp.setId(id);
        vp.addVerifiableCredentials(vcs);
        return await this.issuePresentation(vp, suite, this.loader);
    }
}
