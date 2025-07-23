/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
/*    */
@TableName("markdown")
/*    */ public class MarkdownVo {
    /*    */   private Integer id;
    /*    */   private String album;
    /*    */   private Integer sort;
    /*    */   private String name;
    /*    */   private String md;

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    public void setAlbum(String album) {
        this.album = album;
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setMd(String md) {
        this.md = md;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.MarkdownVo)) return false;
        com.bss.entity.MarkdownVo other = (com.bss.entity.MarkdownVo) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$album = getAlbum(), other$album = other.getAlbum();
        if (!Objects.equals(this$album, other$album)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        return !(!Objects.equals(this$md, other$md));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.MarkdownVo;
    }


    public String toString() {
        return "MarkdownVo(id=" + getId() + ", album=" + getAlbum() + ", sort=" + getSort() + ", name=" + getName() + ", md=" + getMd() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    public String getAlbum() {
        /* 17 */
        return this.album;
        /*    */
    }

    public Integer getSort() {
        /* 19 */
        return this.sort;
        /*    */
    }

    public String getName() {
        /* 21 */
        return this.name;
        /*    */
    }

    public String getMd() {
        /* 23 */
        return this.md;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\MarkdownVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */