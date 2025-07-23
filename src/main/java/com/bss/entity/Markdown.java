/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import com.bss.enmus.AlbumEnum;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("markdown")
/*    */ public class Markdown implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private AlbumEnum album;
    /*    */   private Integer sort;
    /*    */   private String name;
    /*    */   private String md;
    private Integer look;
    private Integer home;
    private Integer state;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Markdown)) return false;
        com.bss.entity.Markdown other = (com.bss.entity.Markdown) o;
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
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$look = getLook(), other$look = other.getLook();
        if (!Objects.equals(this$look, other$look)) return false;
        Object this$home = getHome(), other$home = other.getHome();
        if (!Objects.equals(this$home, other$home)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Markdown;
    }


    public String toString() {
        return "Markdown(id=" + getId() + ", album=" + getAlbum() + ", sort=" + getSort() + ", name=" + getName() + ", md=" + getMd() + ", look=" + getLook() + ", home=" + getHome() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 19 */
        return this.id;
        /*    */
    }

    /*    */
    /* 16 */
    public void setId(Integer id) {
        this.id = id;
    }

    public AlbumEnum getAlbum() {
        /* 21 */
        return this.album;
        /*    */
    }

    public void setAlbum(AlbumEnum album) {
        this.album = album;
    }

    public Integer getSort() {
        /* 23 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getName() {
        /* 25 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getMd() {
        /* 27 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }

    public Integer getLook() {
        /* 29 */
        return this.look;
        /*    */
    }

    public void setLook(Integer look) {
        this.look = look;
    }

    public Integer getHome() {
        /* 31 */
        return this.home;
        /*    */
    }

    public void setHome(Integer home) {
        this.home = home;
    }

    public Integer getState() {
        /* 33 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public String getCreateTime() {
        /* 35 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Markdown.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */