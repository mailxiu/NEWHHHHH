/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */ public class RecordCount {
    /*    */   private String name;
    /*    */   private String image;
    /*    */   private String code;
    /*    */   private Integer countAll;
    /*    */   private Integer countTrue;
    /*    */   private Integer countFalse;

    public RecordCount(String name, String image, String code, Integer countAll, Integer countTrue, Integer countFalse) {
        /* 12 */
        this.name = name;
        this.image = image;
        this.code = code;
        this.countAll = countAll;
        this.countTrue = countTrue;
        this.countFalse = countFalse;
        /*    */
    }

    /*    */
    public RecordCount() {
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.RecordCount)) return false;
        com.bss.entity.RecordCount other = (com.bss.entity.RecordCount) o;
        if (!other.canEqual(this)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$countAll = getCountAll(), other$countAll = other.getCountAll();
        if (!Objects.equals(this$countAll, other$countAll)) return false;
        Object this$countTrue = getCountTrue(), other$countTrue = other.getCountTrue();
        if (!Objects.equals(this$countTrue, other$countTrue))
            return false;
        Object this$countFalse = getCountFalse(), other$countFalse = other.getCountFalse();
        return !(!Objects.equals(this$countFalse, other$countFalse));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.RecordCount;
    }


    public String toString() {
        return "RecordCount(name=" + getName() + ", image=" + getImage() + ", code=" + getCode() + ", countAll=" + getCountAll() + ", countTrue=" + getCountTrue() + ", countFalse=" + getCountFalse() + ")";
    }

    /*    */
    public String getName() {
        /* 16 */
        return this.name;
        /*    */
    }

    /*    */
    /* 11 */
    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 18 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public String getCode() {
        /* 20 */
        return this.code;
        /*    */
    }

    public void setCode(String code) {
        this.code = code;
    }

    public Integer getCountAll() {
        /* 22 */
        return this.countAll;
        /*    */
    }

    public void setCountAll(Integer countAll) {
        this.countAll = countAll;
    }

    public Integer getCountTrue() {
        /* 24 */
        return this.countTrue;
        /*    */
    }

    public void setCountTrue(Integer countTrue) {
        this.countTrue = countTrue;
    }

    public Integer getCountFalse() {
        /* 26 */
        return this.countFalse;
        /*    */
    }

    public void setCountFalse(Integer countFalse) {
        this.countFalse = countFalse;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\RecordCount.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */