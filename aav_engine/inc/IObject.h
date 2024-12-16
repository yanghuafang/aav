#ifndef _IOBJECT_H_
#define _IOBJECT_H_

class IObject {
 public:
  virtual int retain() = 0;
  virtual int release() = 0;
};

#endif